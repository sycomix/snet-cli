import web3
from snet.sdk.payment_strategies.default import PaymentChannelManagementStrategy
from snet.sdk.payment_strategies.payment_staregy import PaymentStrategy


class FreeCallPaymentStrategy(PaymentStrategy):

    def is_free_call_available(self,service_client):
        #TODO get free call from daemon



        return True

    def get_payment_metadata(self, service_client):

        if self.is_free_call_available(service_client):
            #TODO integration test with daemon for free call
            auth_token=b'\xe6\xa5s\xb4D\xb5\xad\x86\x9d\xbd\xc4\x16N}\xc7 \x81\xe3\xbae0|\xa1\xdcK}\x81\xc2*\xb2\xab\x92\x08m\xa16\xd3mr]C\x95j\x1d\xdd\xa2\xc9\xd9\x8d\xde\x12\xc4\xb1!+\xea\x97=o)x\xde\xa6Q\x1c'
            org_id = "ar3"
            service_id = "freecall"
            group_id = "qY1r6474PbBZ8lu4IhTbQ+e00dT4WsASt7vBILVTDvU="
            cbn = service_client.sdk_web3.eth.getBlock("latest").number
            message = web3.Web3.soliditySha3(
                ["string", "string", "string", "string", "string", "uint256", "bytes32"],
                ["__prefix_free_trial", "sumitk002@gmail.com", org_id, service_id, group_id, 7313767, auth_token]
            )
            signature = service_client.generate_signature(message)
            print(signature)


            metadata = [("snet-free-call-auth-token-bin", auth_token),
                ("snet-free-call-token-expiry-block", str(7313767)),
                        ("snet-payment-type","free-call"),
                        ("snet-free-call-user-id","sumitk002@gmail.com"),
                        ("snet-current-block-number", str(7313767)),
                        ("snet-payment-channel-signature-bin",signature)

            ]

        else:
            payment_strategy = PaymentChannelManagementStrategy()
            metadata = payment_strategy.get_payment_metadata(service_client)

        return metadata

    def select_channel(self,service_client):
        pass

