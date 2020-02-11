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
            auth_token=b'w{7\x8c\xa4\xe1\xbaC;uG\xf6C\x8dF&\xe6NBv\x0c\xdf\xdcc\x1bI\x7f\x14\x01#\xdf\x87Z\x16\xdeu5\x90\x1bt\x8e\x15\xfb\xf2j\x1e\x0e\xb4\xc5\xea\x88\xd6\xd7O]\x92\xeb\xee\xbaR\xc5K\xca\x1d\x1b'
            org_id = "ar3"
            service_id = "freecall"
            group_id = "qY1r6474PbBZ8lu4IhTbQ+e00dT4WsASt7vBILVTDvU="
            cbn = service_client.sdk_web3.eth.getBlock("latest").number
            message = web3.Web3.soliditySha3(
                ["string", "string", "string", "string", "string", "uint256", "bytes32"],
                ["__prefix_free_trial", "sumitk002@gmail.com", org_id, service_id, group_id, 7304886, auth_token]
            )
            signature = service_client.generate_signature(message)


            metadata = [("snet-free-call-auth-token-bin", auth_token),
                ("snet-free-call-token-issue-block", str(7304886)),
                        ("snet-payment-type","free-call"),
                        ("snet-free-call-user-id","sumitk002@gmail.com"),
                        ("snet-current-block-number", str(7304886)),
                        ("snet-payment-channel-signature-bin",signature)

            ]

        else:
            payment_strategy = PaymentChannelManagementStrategy()
            metadata = payment_strategy.get_payment_metadata(service_client)

        return metadata

    def select_channel(self,service_client):
        pass

