import base64
import getpass
import json
import secrets
import sys
from textwrap import indent
from urllib.parse import urljoin

import ipfsapi
import yaml
from rfc3986 import urlparse
from snet.snet_cli.contract import Contract
from snet.snet_cli.metadata.organization import OrganizationMetadata, PaymentStorageClient, Payment, Group
from snet.snet_cli.utils.ipfs_utils import bytesuri_to_hash, get_from_ipfs_and_checkhash, hash_to_bytesuri
from snet.snet_cli.utils.ipfs_utils import publish_file_in_ipfs
from snet.snet_cli.utils.utils import DefaultAttributeObject, get_web3, serializable, type_converter, get_contract_def, \
    get_cli_version, bytes32_to_str
from snet_cli.identity import RpcIdentityProvider, MnemonicIdentityProvider, TrezorIdentityProvider, \
    LedgerIdentityProvider, KeyIdentityProvider, KeyStoreIdentityProvider
from snet_cli.identity import get_kws_for_identity_type
from snet_cli.utils.config import get_contract_address, get_field_from_args_or_session, read_default_contract_address
from web3.eth import is_checksum_address
from web3.gas_strategies.time_based import fast_gas_price_strategy, medium_gas_price_strategy, slow_gas_price_strategy


class Command(object):
    def __init__(self, config, args, out_f=sys.stdout, err_f=sys.stderr):
        self.config = config
        self.args = args
        self.out_f = out_f
        self.err_f = err_f

    def _error(self, message):
        self._printerr(f"ERROR: {message}")
        sys.exit(1)

    def _ensure(self, condition, message):
        if not condition:
            self._error(message)

    @staticmethod
    def _print(message, fd):
        message = str(message) + "\n"
        try:
            fd.write(message)
        except UnicodeEncodeError:
            if hasattr(fd, "buffer"):
                fd.buffer.write(message.encode("utf-8"))
            else:
                raise

    def _printout(self, message):
        if self.out_f is not None:
            self._print(message, self.out_f)

    def _printerr(self, message):
        if self.err_f is not None:
            self._print(message, self.err_f)

    def _pprint(self, item):
        self._printout(indent(yaml.dump(json.loads(json.dumps(item, default=serializable)), default_flow_style=False,
                                        indent=4), "    "))

    def _pprint_receipt_and_events(self, receipt, events):
        if self.args.verbose:
            self._pprint({"receipt": receipt, "events": events})
        elif self.args.quiet:
            self._pprint({"transactionHash": receipt["transactionHash"]})
        else:
            self._pprint({"receipt_summary": {"blockHash": receipt["blockHash"],
                                              "blockNumber": receipt["blockNumber"],
                                              "cumulativeGasUsed": receipt["cumulativeGasUsed"],
                                              "gasUsed": receipt["gasUsed"],
                                              "transactionHash": receipt["transactionHash"]},
                          "event_summaries": [{"args": e["args"], "event": e["event"]} for e in events]})

    def _get_ipfs_client(self):
        ipfs_endpoint = urlparse(self.config.get_ipfs_endpoint())
        ipfs_scheme = ipfs_endpoint.scheme if ipfs_endpoint.scheme else "http"
        ipfs_port = ipfs_endpoint.port if ipfs_endpoint.port else 5001
        return ipfsapi.connect(urljoin(ipfs_scheme, ipfs_endpoint.hostname), ipfs_port)


class VersionCommand(Command):
    def show(self):
        self._pprint({"version": get_cli_version()})


class CachedGasPriceStrategy:
    def __init__(self, gas_price_param):
        self.gas_price_param = gas_price_param
        self.cached_gas_price = None

    def __call__(self, w3, transaction_params):
        if self.cached_gas_price is None:
            self.cached_gas_price = int(
                self.calc_gas_price(w3, transaction_params))
        return self.cached_gas_price

    def calc_gas_price(self, w3, transaction_params):
        gas_price_param = self.gas_price_param
        if gas_price_param.isdigit():
            return int(self.gas_price_param)
        if gas_price_param == "fast":
            return fast_gas_price_strategy(w3, transaction_params)
        if gas_price_param == "medium":
            return medium_gas_price_strategy(w3, transaction_params)
        if gas_price_param == "slow":
            return slow_gas_price_strategy(w3, transaction_params)
        raise Exception(f"Unknown gas price strategy: {gas_price_param}")

    def is_going_to_calculate(self):
        return self.cached_gas_price is None and not self.gas_price_param.isdigit()


class BlockchainCommand(Command):
    def __init__(self, config, args, out_f=sys.stdout, err_f=sys.stderr, w3=None, ident=None):
        super(BlockchainCommand, self).__init__(config, args, out_f, err_f)
        self.w3 = w3 or get_web3(self.get_eth_endpoint())
        self.ident = ident or self.get_identity()
        if type(self.w3.eth.gasPriceStrategy) != CachedGasPriceStrategy:
            self.w3.eth.setGasPriceStrategy(
                CachedGasPriceStrategy(self.get_gas_price_param()))

    def get_eth_endpoint(self):
        # the only one source of eth_rpc_endpoint is the configuration file
        return self.config.get_session_field("default_eth_rpc_endpoint")

    def get_wallet_index(self):
        return int(get_field_from_args_or_session(self.config, self.args, "wallet_index"))

    def get_gas_price_param(self):
        return get_field_from_args_or_session(self.config, self.args, "gas_price")

    def get_gas_price_verbose(self):
        # gas price is not given explicitly in Wei
        if self.w3.eth.gasPriceStrategy.is_going_to_calculate():
            self._printerr(
                "# Calculating gas price. It might take ~60 seconds.")
        g = self.w3.eth.generateGasPrice()
        self._printerr("# gas_price = %f GWei" % (g * 1E-9))
        return g

    def get_mpe_address(self):
        return get_contract_address(self, "MultiPartyEscrow")

    def get_registry_address(self):
        return get_contract_address(self, "Registry")

    def get_identity(self):
        identity_type = self.config.get_session_field("identity_type")

        if identity_type == "rpc":
            return RpcIdentityProvider(self.w3, self.get_wallet_index())
        if identity_type == "mnemonic":
            return MnemonicIdentityProvider(self.w3, self.config.get_session_field("mnemonic"), self.get_wallet_index())
        if identity_type == "trezor":
            return TrezorIdentityProvider(self.w3, self.get_wallet_index())
        if identity_type == "ledger":
            return LedgerIdentityProvider(self.w3, self.get_wallet_index())
        if identity_type == "key":
            return KeyIdentityProvider(self.w3, self.config.get_session_field("private_key"))
        if identity_type == "keystore":
            return KeyStoreIdentityProvider(self.w3, self.config.get_session_field("keystore_path"))

    def get_contract_argser(self, contract_address, contract_function, contract_def, **kwargs):
        def f(*positional_inputs, **named_inputs):
            args_dict = self.args.__dict__.copy()
            args_dict.update(dict(
                at=contract_address,
                contract_function=contract_function,
                contract_def=contract_def,
                contract_positional_inputs=positional_inputs,
                **kwargs
            ))
            for k, v in named_inputs.items():
                args_dict["contract_named_input_{}".format(k)] = v
            return DefaultAttributeObject(**args_dict)

        return f

    def get_contract_command(self, contract_name, contract_address, contract_fn, contract_params, is_silent=True):
        contract_def = get_contract_def(contract_name)
        if is_silent:
            out_f = None
            err_f = None
        else:
            out_f = self.out_f
            err_f = self.err_f
        return ContractCommand(config=self.config,
                               args=self.get_contract_argser(
                                   contract_address=contract_address,
                                   contract_function=contract_fn,
                                   contract_def=contract_def,
                                   contract_name=contract_name)(*contract_params),
                               out_f=out_f,
                               err_f=err_f,
                               w3=self.w3,
                               ident=self.ident)

    def call_contract_command(self, contract_name, contract_fn, contract_params, is_silent=True):
        contract_address = get_contract_address(self, contract_name)
        return self.get_contract_command(contract_name, contract_address,
                                         contract_fn, contract_params, is_silent).call()

    def transact_contract_command(self, contract_name, contract_fn, contract_params, is_silent=False):
        contract_address = get_contract_address(self, contract_name)
        return self.get_contract_command(contract_name, contract_address, contract_fn, contract_params,
                                         is_silent).transact()


class IdentityCommand(Command):
    def create(self):
        identity_name = self.args.identity_name
        self._ensure(
            identity_name not in self.config.get_all_identities_names(),
            f"identity_name {identity_name} already exists",
        )

        identity_type = self.args.identity_type
        identity = {"identity_type": identity_type}
        for kw, is_secret in get_kws_for_identity_type(identity_type):
            value = getattr(self.args, kw)
            if value is None and is_secret:
                kw_prompt = f'{" ".join(kw.capitalize().split("_"))}: '
                value = getpass.getpass(kw_prompt) or None
            self._ensure(
                value is not None,
                f"--{kw} is required for identity_type {identity_type}",
            )
            identity[kw] = value

        if self.args.network:
            identity["network"] = self.args.network
        identity["default_wallet_index"] = self.args.wallet_index
        self.config.add_identity(identity_name, identity, self.out_f)

    def list(self):
        for identity_section in filter(lambda x: x.startswith("identity."), self.config.sections()):
            identity = self.config[identity_section]
            identity_type = self.config.get(identity_section, 'identity_type')
            key_is_secret_lookup = dict(get_kws_for_identity_type(identity_type))
            self._pprint({
                identity_section[len("identity."):]: {
                    k: (v if not key_is_secret_lookup.get(k, False) else "xxxxxx") for k, v in identity.items()
                }
            })

    def delete(self):
        self.config.delete_identity(self.args.identity_name)

    def set(self):
        self.config.set_session_identity(self.args.identity_name, self.out_f)


class NetworkCommand(Command):
    def list(self):
        for network_section in filter(lambda x: x.startswith("network."), self.config.sections()):
            network = self.config[network_section]
            self._pprint({network_section[len("network."):]: dict(network.items())})

    def create(self):
        network_id = None
        if not self.args.skip_check:
            # check endpoint by getting its network_id
            w3 = get_web3(self.args.eth_rpc_endpoint)
            network_id = w3.version.network

        self._printout(
            f"add network with name='{self.args.network_name}' with networkId='{str(network_id)}'"
        )
        self.config.add_network(
            self.args.network_name, self.args.eth_rpc_endpoint, self.args.default_gas_price)

    def set(self):
        self.config.set_session_network(self.args.network_name, self.out_f)


class SessionSetCommand(Command):
    def set(self):
        self.config.set_session_field(
            self.args.key, self.args.value, self.out_f)

    def unset(self):
        self.config.unset_session_field(self.args.key, self.out_f)


class SessionShowCommand(BlockchainCommand):
    def show(self):
        rez = self.config.session_to_dict()
        key = f"network.{rez['session']['network']}"
        self.populate_contract_address(rez, key)

        # we don't want to who private_key and mnemonic
        for d in rez.values():
            d.pop("private_key", None)
            d.pop("mnemonic", None)
        self._pprint(rez)

    def populate_contract_address(self, rez, key):
        try:
            rez[key]['default_registry_at'] = read_default_contract_address(
                w3=self.w3, contract_name="Registry")
            rez[key]['default_multipartyescrow_at'] = read_default_contract_address(
                w3=self.w3, contract_name="MultiPartyEscrow")
            rez[key]['default_singularitynettoken_at'] = read_default_contract_address(
                w3=self.w3, contract_name="SingularityNetToken")
        except Exception as e:
            pass
        return


class ContractCommand(BlockchainCommand):
    def call(self):
        contract_address = get_contract_address(self, self.args.contract_name,
                                                "--at is required to specify target contract address")

        abi = self.args.contract_def["abi"]

        contract = Contract(self.w3, contract_address, abi)

        positional_inputs = getattr(
            self.args, "contract_positional_inputs", [])
        named_inputs = {
            name[len("contract_named_input_"):]: value for name, value
            in self.args.__dict__.items() if name.startswith("contract_named_input_")
        }

        result = contract.call(self.args.contract_function,
                               *positional_inputs, **named_inputs)
        self._printout(result)
        return result

    def transact(self):
        contract_address = get_contract_address(self, self.args.contract_name,
                                                "--at is required to specify target contract address")

        abi = self.args.contract_def["abi"]

        contract = Contract(self.w3, contract_address, abi)

        positional_inputs = getattr(
            self.args, "contract_positional_inputs", [])
        named_inputs = {
            name[len("contract_named_input_"):]: value for name, value
            in self.args.__dict__.items() if name.startswith("contract_named_input_")
        }

        gas_price = self.get_gas_price_verbose()

        txn = contract.build_transaction(self.args.contract_function,
                                         self.ident.get_address(),
                                         gas_price,
                                         *positional_inputs,
                                         **named_inputs)

        if not self.args.yes or self.args.verbose:
            self._pprint({"transaction": txn})

        if proceed := self.args.yes or input("Proceed? (y/n): ") == "y":
            receipt = self.ident.transact(txn, self.err_f)
            events = contract.process_receipt(receipt)
            self._pprint_receipt_and_events(receipt, events)
            return receipt, events
        else:
            self._error("Cancelled")


class OrganizationCommand(BlockchainCommand):

    def add_group(self):
        metadata_file = self.args.metadata_file

        try:
            with open(metadata_file, 'r') as f:
                org_metadata = OrganizationMetadata.from_json(json.load(f))
        except Exception as e:
            print(
                "Organization metadata json file not found ,Please check --metadata-file path ")
            raise e

        payment_storage_client = PaymentStorageClient(self.args.payment_channel_connection_timeout,
                                                      self.args.payment_channel_request_timeout, self.args.endpoints)
        payment = Payment(self.args.payment_address, self.args.payment_expiration_threshold,
                          self.args.payment_channel_storage_type, payment_storage_client)
        group_id = base64.b64encode(secrets.token_bytes(32))

        group = Group(self.args.group_name, group_id.decode("ascii"), payment)
        org_metadata.add_group(group)
        org_metadata.save_pretty(metadata_file)

    def remove_group(self):
        group_id = self.args.group_id
        metadata_file = self.args.metadata_file

        try:
            with open(metadata_file, 'r') as f:
                org_metadata = OrganizationMetadata.from_json(json.load(f))
        except Exception as e:
            print(
                "Organization metadata json file not found ,Please check --metadata-file path ")
            raise e

        existing_groups = org_metadata.groups
        updated_groups = [
            group for group in existing_groups if group_id != group.group_id
        ]
        org_metadata.groups = updated_groups
        org_metadata.save_pretty(metadata_file)

    def set_changed_values_for_group(self, group):
        # if value of a parameter is None that means it was not updated

        if self.args.endpoints:
            group.update_endpoints(self.args.endpoints)
        if self.args.payment_address:
            group.update_payment_address(self.args.payment_address)
        if self.args.payment_expiration_threshold:
            group.update_payment_expiration_threshold(
                self.args.payment_expiration_threshold)
        if self.args.payment_channel_storage_type:
            group.update_payment_channel_storage_type(
                self.args.payment_channel_storage_type)
        if self.args.payment_channel_connection_timeout:
            group.update_connection_timeout(
                self.args.payment_channel_connection_timeout)
        if self.args.payment_channel_request_timeout:
            group.update_request_timeout(
                self.args.payment_channel_request_timeout)

    def update_group(self):
        group_id = self.args.group_id
        metadata_file = self.args.metadata_file
        try:
            with open(metadata_file, 'r') as f:
                org_metadata = OrganizationMetadata.from_json(json.load(f))
        except Exception as e:
            print(
                "Organization metadata json file not found ,Please check --metadata-file path ")
            raise e
        existing_groups = org_metadata.groups
        for group in existing_groups:
            if group_id == group.group_id:
                self.set_changed_values_for_group(group)

        org_metadata.save_pretty(metadata_file)

    def initialize_metadata(self):
        org_id = self.args.org_id
        metadata_file_name = self.args.metadata_file

        if found := self._get_organization_by_id(org_id)[0]:
            raise Exception(f"\nOrganization with id={org_id} already exists!\n")
        org_metadata = OrganizationMetadata(self.args.org_name, org_id, self.args.org_type)
        org_metadata.save_pretty(metadata_file_name)

    def print_metadata(self):
        org_id = self.args.org_id
        org_metadata = self._get_organization_metadata_from_registry(org_id)
        self._printout(org_metadata.get_json_pretty())

    def _get_organization_registration(self, org_id):
        params = [type_converter("bytes32")(org_id)]
        rez = self.call_contract_command(
            "Registry", "getOrganizationById", params)
        if not rez[0]:
            raise Exception(f"Cannot find  Organization with id={self.args.org_id}")
        return {"orgMetadataURI": rez[2]}

    def _get_organization_metadata_from_registry(self, org_id):
        rez = self._get_organization_registration(org_id)
        metadata_hash = bytesuri_to_hash(rez["orgMetadataURI"])
        metadata = get_from_ipfs_and_checkhash(
            self._get_ipfs_client(), metadata_hash)
        metadata = metadata.decode("utf-8")
        return OrganizationMetadata.from_json(json.loads(metadata))

    def _get_organization_by_id(self, org_id):
        org_id_bytes32 = type_converter("bytes32")(org_id)
        if len(org_id_bytes32) > 32:
            raise Exception("Your org_id is too long, it should be 32 bytes or less. len(org_id_bytes32)=%i" % (
                len(org_id_bytes32)))
        return self.call_contract_command("Registry", "getOrganizationById", [org_id_bytes32])

    # TODO: It would be better to have standard nargs="+" in argparse for members.
    #      But we keep comma separated members for backward compatibility
    def get_members_from_args(self):
        if not self.args.members:
            return []
        members = [m.replace("[", "").replace("]", "")
                   for m in self.args.members.split(',')]
        for m in members:
            if not is_checksum_address(m):
                raise Exception(f"Member account {m} is not a valid Ethereum checksum address")
        return members

    def list(self):
        org_list = self.call_contract_command(
            "Registry", "listOrganizations", [])

        self._printout("# OrgId")
        for org_id in org_list:
            self._printout(bytes32_to_str(org_id))

    def list_org_name(self):
        org_list = self.call_contract_command(
            "Registry", "listOrganizations", [])

        self._printout("# OrgName OrgId")
        for idx, org_id in enumerate(org_list):
            rez = self.call_contract_command(
                "Registry", "getOrganizationById", [org_id])
            if not rez[0]:
                raise Exception(
                    "Organization was removed during this call. Please retry.")
            org_name = rez[2]
            self._printout(f"{org_name}  {bytes32_to_str(org_id)}")

    def error_organization_not_found(self, org_id, found):
        if not found:
            raise Exception(f"Organization with id={org_id} doesn't exist!\n")

    def info(self):
        org_id = self.args.org_id
        (found, org_id, org_name, owner, members, serviceNames) = self._get_organization_by_id(org_id)
        self.error_organization_not_found(self.args.org_id, found)

        self._printout("\nOrganization Name:\n - %s" % org_name)
        self._printout("\nOrganization Id:\n - %s" % bytes32_to_str(org_id))
        self._printout(f"\nOwner:\n - {owner}")
        if members:
            self._printout("\nMembers:")
            for member in members:
                self._printout(f" - {member}")
        if serviceNames:
            self._printout("\nServices:")
            for service in serviceNames:
                self._printout(f" - {bytes32_to_str(service)}")

    def create(self):

        metadata_file = self.args.metadata_file

        try:
            with open(metadata_file, 'r') as f:
                org_metadata = OrganizationMetadata.from_json(json.load(f))
        except Exception as e:
            print(
                "Organization metadata json file not found ,Please check --metadata-file path ")
            raise e
        org_id = self.args.org_id
        # validate the metadata before creating
        org_metadata.validate()

        if found := self._get_organization_by_id(org_id)[0]:
            raise Exception(f"\nOrganization with id={org_id} already exists!\n")

        members = self.get_members_from_args()

        ipfs_metadata_uri = publish_file_in_ipfs(
            self._get_ipfs_client(), metadata_file, False)
        params = [type_converter("bytes32")(
            org_id), hash_to_bytesuri(ipfs_metadata_uri), members]
        self._printout(
            f"Creating transaction to create organization name={org_metadata.org_name} id={org_id}\n"
        )
        self.transact_contract_command(
            "Registry", "createOrganization", params)
        self._printout("id:\n%s" % org_id)

    def delete(self):
        org_id = self.args.org_id
        # Check if Organization exists
        (found, _, org_name, _, _, _) = self._get_organization_by_id(org_id)
        self.error_organization_not_found(org_id, found)

        self._printout(
            f"Creating transaction to delete organization with name={org_name} id={org_id}"
        )
        try:
            self.transact_contract_command("Registry", "deleteOrganization", [
                type_converter("bytes32")(org_id)])
        except Exception as e:
            self._printerr(
                f"\nTransaction error!\nHINT: Check if you are the owner of organization with id={org_id}\n"
            )
            raise

    def update_metadata(self):
        metadata_file = self.args.metadata_file

        try:
            with open(metadata_file, 'r') as f:
                org_metadata = OrganizationMetadata.from_json(json.load(f))
        except Exception as e:
            print(
                "Organization metadata json file not found ,Please check --metadata-file path ")
            raise e
        # validate the metadata before updating

        org_id = self.args.org_id
        existing_registry_org_metadata = self._get_organization_metadata_from_registry(
            org_id)
        org_metadata.validate(existing_registry_org_metadata)

        # Check if Organization already exists
        found = self._get_organization_by_id(org_id)[0]
        if not found:
            raise Exception(f"\nOrganization with id={org_id} does not  exists!\n")

        ipfs_metadata_uri = publish_file_in_ipfs(
            self._get_ipfs_client(), metadata_file, False)
        params = [type_converter("bytes32")(
            org_id), hash_to_bytesuri(ipfs_metadata_uri)]
        self._printout(
            f"Creating transaction to create organization name={org_metadata.org_name} id={org_id}\n"
        )
        self.transact_contract_command(
            "Registry", "changeOrganizationMetadataURI", params)
        self._printout("id:\n%s" % org_id)

    def list_services(self):
        org_id = self.args.org_id
        (found, org_service_list) = self.call_contract_command("Registry", "listServicesForOrganization",
                                                               [type_converter("bytes32")(org_id)])
        self.error_organization_not_found(org_id, found)
        if org_service_list:
            self._printout(f"\nList of {org_id}'s Services:")
            for org_service in org_service_list:
                self._printout(f"- {bytes32_to_str(org_service)}")
        else:
            self._printout(
                f"Organization with id={org_id} exists but has no registered services."
            )

    def change_owner(self):
        org_id = self.args.org_id
        # Check if Organization exists
        (found, _, _, owner, _, _) = self._get_organization_by_id(org_id)
        self.error_organization_not_found(org_id, found)

        new_owner = self.args.owner
        if not is_checksum_address(new_owner):
            raise Exception(
                f"New owner account {new_owner} is not a valid Ethereum checksum address"
            )

        if new_owner.lower() == owner.lower():
            raise Exception(
                f"\n{new_owner} is the owner of Organization with id={org_id}!\n"
            )

        self._printout(
            f"Creating transaction to change organization {org_id}'s owner...\n"
        )
        try:
            self.transact_contract_command("Registry", "changeOrganizationOwner",
                                           [type_converter("bytes32")(org_id), self.args.owner])
        except Exception as e:
            self._printerr(
                f"\nTransaction error!\nHINT: Check if you are the owner of {org_id}\n"
            )
            raise

    def add_members(self):
        org_id = self.args.org_id
        # Check if Organization exists and member is not part of it
        (found, _, _, _, members, _) = self._get_organization_by_id(org_id)
        self.error_organization_not_found(org_id, found)

        members = [member.lower() for member in members]
        add_members = []
        for add_member in self.get_members_from_args():
            if add_member.lower() in members:
                self._printout(f"{add_member} is already a member of organization {org_id}")
            else:
                add_members.append(add_member)

        if not add_members:
            self._printout(f"No member was added to {org_id}!\n")
            return

        params = [type_converter("bytes32")(org_id), add_members]
        self._printout(
            f"Creating transaction to add {len(add_members)} members into organization {org_id}...\n"
        )
        try:
            self.transact_contract_command(
                "Registry", "addOrganizationMembers", params)
        except Exception as e:
            self._printerr(
                f"\nTransaction error!\nHINT: Check if you are the owner of {org_id}\n"
            )
            raise

    def rem_members(self):
        org_id = self.args.org_id
        # Check if Organization exists and member is part of it
        (found, _, _, _, members, _) = self._get_organization_by_id(org_id)
        self.error_organization_not_found(org_id, found)

        members = [member.lower() for member in members]
        rem_members = []
        for rem_member in self.get_members_from_args():
            if rem_member.lower() not in members:
                self._printout(f"{rem_member} is not a member of organization {org_id}")
            else:
                rem_members.append(rem_member)

        if not rem_members:
            self._printout(f"No member was removed from {org_id}!\n")
            return

        params = [type_converter("bytes32")(org_id), rem_members]
        self._printout(
            f"Creating transaction to remove {len(rem_members)} members from organization with id={org_id}...\n"
        )
        try:
            self.transact_contract_command(
                "Registry", "removeOrganizationMembers", params)
        except Exception as e:
            self._printerr(
                f"\nTransaction error!\nHINT: Check if you are the owner of {org_id}\n"
            )
            raise

    def list_my(self):
        """ Find organization that has the current identity as the owner or as the member """
        org_list = self.call_contract_command(
            "Registry", "listOrganizations", [])

        rez_owner = []
        rez_member = []
        for org_id in org_list:
            (found, org_id, org_name, owner, members, serviceNames) = self.call_contract_command(
                "Registry", "getOrganizationById", [org_id])
            if not found:
                raise Exception(
                    "Organization was removed during this call. Please retry.")
            if self.ident.address == owner:
                rez_owner.append((org_name, bytes32_to_str(org_id)))

            if self.ident.address in members:
                rez_member.append((org_name, bytes32_to_str(org_id)))

        if rez_owner:
            self._printout("# Organizations you are the owner of")
            self._printout("# OrgName OrgId")
            for n, i in rez_owner:
                self._printout(f"{n}   {i}")

        if rez_member:
            self._printout("# Organizations you are the member of")
            self._printout("# OrgName OrgId")
            for n, i in rez_member:
                self._printout(f"{n}   {i}")

    def metadata_add_asset_to_ipfs(self):
        metadata_file = self.args.metadata_file
        org_metadata = OrganizationMetadata.from_file(metadata_file)
        asset_file_ipfs_hash_base58 = publish_file_in_ipfs(self._get_ipfs_client(),
                                                                      self.args.asset_file_path)

        org_metadata.add_asset(asset_file_ipfs_hash_base58, self.args.asset_type)
        org_metadata.save_pretty(self.args.metadata_file)

    def metadata_remove_assets_of_a_given_type(self):
        metadata_file = self.args.metadata_file
        org_metadata = OrganizationMetadata.from_file(metadata_file)
        org_metadata.remove_assets(self.args.asset_type)
        org_metadata.save_pretty(self.args.metadata_file)

    def metadata_remove_all_assets(self):
        metadata_file = self.args.metadata_file
        org_metadata = OrganizationMetadata.from_file(metadata_file)
        org_metadata.remove_all_assets()
        org_metadata.save_pretty(self.args.metadata_file)

    def metadata_add_description(self):
        description = self.args.description
        url = self.args.url
        short_description = self.args.short_description
        metadata_file = self.args.metadata_file
        org_metadata = OrganizationMetadata.from_file(metadata_file)
        if description:
            org_metadata.add_description(description)
        if short_description:
            org_metadata.add_short_description(short_description)
        if url:
            org_metadata.add_url(url)
        if description is None and url is None and short_description is None:
            raise Exception("No attributes are given")
        org_metadata.save_pretty(metadata_file)

    def metadata_add_contact(self):
        args = self.args.__dict__
        metadata_file = args["metadata_file"]
        contact_type = args.get("contact_type", None)
        phone = args.get("phone", None)
        email = args.get("email", None)
        if phone is None and email is None:
            self._printout("email and phone both can not be empty")
        else:
            org_metadata = OrganizationMetadata.from_file(metadata_file)
            org_metadata.add_contact(contact_type, phone, email)
            org_metadata.save_pretty(metadata_file)

    def metadata_remove_contact_by_type(self):
        metadata_file = self.args.metadata_file
        contact_type = self.args.contact_type
        org_metadata = OrganizationMetadata.from_file(metadata_file)
        org_metadata.remove_contact_by_type(contact_type)
        org_metadata.save_pretty(metadata_file)

    def metadata_remove_all_contacts(self):
        metadata_file = self.args.metadata_file
        org_metadata = OrganizationMetadata.from_file(metadata_file)
        org_metadata.remove_all_contacts()
        org_metadata.save_pretty(metadata_file)
