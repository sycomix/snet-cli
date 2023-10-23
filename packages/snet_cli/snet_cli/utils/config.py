from snet.snet_cli.utils.utils import get_contract_def


def get_contract_address(cmd, contract_name, error_message=None):
    """
    We try to get config address from the different sources.
    The order of priorioty is following:
    - command line argument (at)
    - command line argument (<contract_name>_at)
    - current session configuration (current_<contract_name>_at)
    - networks/*json
    """

    # try to get from command line argument at or contractname_at
    a = "at"
    if (hasattr(cmd.args, a) and getattr(cmd.args, a)):
        return cmd.w3.toChecksumAddress(getattr(cmd.args, a))

    # try to get from command line argument contractname_at
    a = f"{contract_name.lower()}_at"
    if (hasattr(cmd.args, a) and getattr(cmd.args, a)):
        return cmd.w3.toChecksumAddress(getattr(cmd.args, a))

    if rez := cmd.config.get_session_field(
        f"current_{contract_name.lower()}_at", exception_if_not_found=False
    ):
        return cmd.w3.toChecksumAddress(rez)

    error_message = error_message or "Fail to read %s address from \"networks\", you should " \
                                     "specify address by yourself via --%s_at parameter" % (
                        contract_name, contract_name.lower())
    # try to take address from networks
    return read_default_contract_address(w3=cmd.w3, contract_name=contract_name)


def read_default_contract_address(w3, contract_name):
    chain_id = w3.version.network  # this will raise exception if endpoint is invalid
    contract_def = get_contract_def(contract_name)
    networks = contract_def["networks"]
    contract_address = networks.get(chain_id, {}).get("address", None)
    if not contract_address:
        raise Exception()
    contract_address = w3.toChecksumAddress(contract_address)
    return contract_address


def get_field_from_args_or_session(config, args, field_name):
    """
    We try to get field_name from diffent sources:
    The order of priorioty is following:
   read_default_contract_address - command line argument (--<field_name>)
    - current session configuration (default_<filed_name>)
    """
    rez = getattr(args, field_name, None)
    # type(rez) can be int in case of wallet-index, so we cannot make simply if(rez)
    if rez is not None:
        return rez
    if rez := config.get_session_field(
        f"default_{field_name}", exception_if_not_found=False
    ):
        return rez
    raise Exception(
        f'Fail to get default_{field_name} from config, should specify {field_name} via --{field_name.replace("_", "-")} parameter'
    )
