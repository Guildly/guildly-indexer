from apibara import IndexerRunner, Info, NewBlock, NewEvents
from apibara.indexer.runner import IndexerRunnerConfiguration
from apibara.model import EventFilter

# from pymongo import MongoClient
from starknet_py.contract import FunctionCallSerializer, identifier_manager_from_abi
from typing import Iterator, List, Tuple

from indexer.utils import felt_to_str, str_to_felt

# import deployments_config

indexer_id = "guildly-indexer"

uint256_abi = {
    "name": "Uint256",
    "type": "struct",
    "size": 2,
    "members": [
        {"name": "low", "offset": 0, "type": "felt"},
        {"name": "high", "offset": 1, "type": "felt"},
    ],
}

guild_deploy_abi = {
    "outputs": [
        {"name": "name", "type": "felt"},
        {"name": "master", "type": "felt"},
        {"name": "contract_address", "type": "felt"},
    ],
    "keys": [],
    "name": "GuildContractDeployed",
    "type": "event",
}

permission_abi = {
    "members": [
        {"name": "to", "offset": 0, "type": "felt"},
        {"name": "selector", "offset": 1, "type": "felt"},
    ],
    "name": "Permission",
    "size": 2,
    "type": "struct",
}

transfer_abi = {
    "name": "Transfer",
    "type": "event",
    "keys": [],
    "outputs": [
        {"name": "from_address", "type": "felt"},
        {"name": "to_address", "type": "felt"},
        {"name": "token_id", "type": "Uint256"},
    ],
}

mint_certificate_abi = {
    "outputs": [
        {"name": "account", "type": "felt"},
        {"name": "role", "type": "felt"},
        {"name": "guild", "type": "felt"},
        {"name": "id", "type": "Uint256"},
    ],
    "keys": [],
    "name": "MintCertificate",
    "type": "event",
}

burn_certificate_abi = {
    "outputs": [
        {"name": "account", "type": "felt"},
        {"name": "role", "type": "felt"},
        {"name": "guild", "type": "felt"},
        {"name": "id", "type": "Uint256"},
    ],
    "keys": [],
    "name": "BurnCertificate",
    "type": "event",
}

member_whitelisted_abi = {
    "outputs": [{"name": "account", "type": "felt"}, {"name": "role", "type": "felt"}],
    "keys": [],
    "name": "MemberWhitelisted",
    "type": "event",
}

member_removed_abi = {
    "outputs": [{"name": "account", "type": "felt"}],
    "keys": [],
    "name": "MemberRemoved",
    "type": "event",
}
member_role_updated_abi = {
    "outputs": [
        {"name": "account", "type": "felt"},
        {"name": "new_role", "type": "felt"},
    ],
    "keys": [],
    "name": "MemberRoleUpdated",
    "type": "event",
}
token_ids_abi = {
    "outputs": [
        {"name": "account", "type": "felt"},
        {"name": "token_ids_len", "type": "felt"},
        {"name": "token_ids", "type": "Uint256*"},
    ],
    "keys": [],
    "name": "TokenIds",
    "type": "event",
}
permissions_set_abi = {
    "outputs": [
        {"name": "account", "type": "felt"},
        {"name": "permissions_len", "type": "felt"},
        {"name": "permissions", "type": "Permission*"},
    ],
    "keys": [],
    "name": "PermissionsSet",
    "type": "event",
}
transaction_executed_abi = {
    "outputs": [
        {"name": "account", "type": "felt"},
        {"name": "hash", "type": "felt"},
        {"name": "response_len", "type": "felt"},
        {"name": "response", "type": "felt*"},
    ],
    "keys": [],
    "name": "TransactionExecuted",
    "type": "event",
}

deposited_abi = {
    "outputs": [
        {"name": "account", "type": "felt"},
        {"name": "certificate_id", "type": "Uint256"},
        {"name": "token_standard", "type": "felt"},
        {"name": "token", "type": "felt"},
        {"name": "token_id", "type": "Uint256"},
        {"name": "amount", "type": "Uint256"},
    ],
    "keys": [],
    "name": "Deposited",
    "type": "event",
}

withdrawn_abi = {
    "outputs": [
        {"name": "account", "type": "felt"},
        {"name": "certificate_id", "type": "Uint256"},
        {"name": "token_standard", "type": "felt"},
        {"name": "token", "type": "felt"},
        {"name": "token_id", "type": "Uint256"},
        {"name": "amount", "type": "Uint256"},
    ],
    "keys": [],
    "name": "Withdrawn",
    "type": "event",
}

guild_deploy_decoder = FunctionCallSerializer(
    abi=guild_deploy_abi,
    identifier_manager=identifier_manager_from_abi([guild_deploy_abi]),
)

token_ids_decoder = FunctionCallSerializer(
    abi=token_ids_abi,
    identifier_manager=identifier_manager_from_abi(
        [token_ids_abi, uint256_abi]
    ),
)

permissions_decoder = FunctionCallSerializer(
    abi=permissions_set_abi,
    identifier_manager=identifier_manager_from_abi(
        [permissions_set_abi, permission_abi]
    ),
)

mint_burn_certificate_decoder = FunctionCallSerializer(
    abi=mint_certificate_abi,
    identifier_manager=identifier_manager_from_abi([mint_certificate_abi, uint256_abi]),
)

member_whitelisted_decoder = FunctionCallSerializer(
    abi=member_whitelisted_abi,
    identifier_manager=identifier_manager_from_abi([member_whitelisted_abi]),
)

member_role_updated_decoder = FunctionCallSerializer(
    abi=member_role_updated_abi,
    identifier_manager=identifier_manager_from_abi([member_role_updated_abi]),
)

transaction_executed_decoder = FunctionCallSerializer(
    abi=transaction_executed_abi,
    identifier_manager=identifier_manager_from_abi([transaction_executed_abi]),
)

deposit_withdraw_decoder = FunctionCallSerializer(
    abi=deposited_abi,
    identifier_manager=identifier_manager_from_abi([deposited_abi, uint256_abi]),
)

def _felt_from_iter(it: Iterator[bytes]):
    return int.from_bytes(next(it), "big")


def _uint256_from_iter(it: Iterator[bytes]):
    low = _felt_from_iter(it)
    high = _felt_from_iter(it)
    # return (high << 128) + low
    return low, high

def _permission_from_iter(it: Iterator[bytes]):
    to = _felt_from_iter(it)
    selector = _felt_from_iter(it)
    # return (high << 128) + low
    return to, selector

def decode_permissions_set_event(data):
    data_iter = iter(data)
    input = []
    account = _felt_from_iter(data_iter)
    input.append(account)
    permissions_len = _felt_from_iter(data_iter)
    input.append(permissions_len)
    for _ in range(permissions_len):
        to, selector = _permission_from_iter(data_iter)
        input.append(to)
        input.append(selector)
    return permissions_decoder.to_python(input)


def decode_mint_burn_certificate_event(data):
    data_iter = iter(data)
    account = _felt_from_iter(data_iter)
    role = _felt_from_iter(data_iter)
    guild = _felt_from_iter(data_iter)
    low, high = _uint256_from_iter(data_iter)
    return mint_burn_certificate_decoder.to_python([account, role, guild, low, high])


def decode_transaction_executed_event(data):
    data_iter = iter(data)
    account = _felt_from_iter(data_iter)
    hash = _felt_from_iter(data_iter)
    response_len = _felt_from_iter(data_iter)
    response = []
    for _ in range(response_len):
        value = _felt_from_iter(data_iter)
        response.append(value)
    return transaction_executed_decoder.to_python([account, hash, response_len, response])


def decode_deposit_withdraw_event(data):
    data_iter = iter(data)
    account = _felt_from_iter(data_iter)
    certificate_id_low, certificate_id_high = _uint256_from_iter(data_iter)
    token_standard = _felt_from_iter(data_iter)
    token = _felt_from_iter(data_iter)
    token_id_low, token_id_high = _uint256_from_iter(data_iter)
    amount_low, amount_high = _uint256_from_iter(data_iter)
    return deposit_withdraw_decoder.to_python(
        [
            account,
            certificate_id_low,
            certificate_id_high,
            token_standard,
            token,
            token_id_low,
            token_id_high,
            amount_low,
            amount_high,
        ]
    )


def decode_guild_deploy_event(data):
    data = [int.from_bytes(b, "big") for b in data]
    return guild_deploy_decoder.to_python(data)


def decode_member_whitelisted_event(data):
    data = [int.from_bytes(b, "big") for b in data]
    return member_whitelisted_decoder.to_python(data)


def decode_member_role_updated_event(data):
    data = [int.from_bytes(b, "big") for b in data]
    return member_whitelisted_decoder.to_python(data)


def encode_int_as_bytes(n):
    return n.to_bytes(32, "big")

def encode_permissions_as_bytes(n):
    for i in n:
        i["to"] = i["to"].to_bytes(32, "big")
        i["selector"] = i["selector"].to_bytes(32, "big")
    return n



async def handle_events(info: Info, block_events: NewEvents):
    """Handle a group of events grouped by block."""
    block_time = block_events.block.timestamp

    print(f"Received events for block {block_events.block.number}")

    for event in block_events.events:
        if event.name == "GuildContractDeployed":
            gde = decode_guild_deploy_event(event.data)
            guild_deploy_doc = {
                "name": encode_int_as_bytes(gde.name),
                "master": encode_int_as_bytes(gde.master),
                "address": encode_int_as_bytes(gde.contract_address),
                "timestamp": block_time,
            }
            await info.storage.insert_one("guilds", guild_deploy_doc)
            info.add_event_filters(
                filters=[
                    # EventFilter.from_event_name("MemberWhitelisted", address=gde.contract_address),
                    EventFilter.from_event_name(
                        "MemberRemoved", address=gde.contract_address
                    ),
                    EventFilter.from_event_name(
                        "MemberRoleUpdated", address=gde.contract_address
                    ),
                    EventFilter.from_event_name(
                        "PermissionsSet", address=gde.contract_address
                    ),
                    EventFilter.from_event_name(
                        "TransactionExecuted", address=gde.contract_address
                    ),
                    EventFilter.from_event_name(
                        "Deposited", address=gde.contract_address
                    ),
                    EventFilter.from_event_name(
                        "Withdrawn", address=gde.contract_address
                    ),
                ]
            )
        elif event.name in ["MintCertificate", "BurnCertificate"]:
            mbe = decode_mint_burn_certificate_event(event.data)
            members_doc = {
                "account": encode_int_as_bytes(mbe.account),
                "role": encode_int_as_bytes(mbe.role),
                "guild": encode_int_as_bytes(mbe.guild),
                "token_id": encode_int_as_bytes(mbe.id),
                "timestamp": block_time,
            }
            if event.name == "MintCertificate":
                await info.storage.insert_one("members", members_doc)
            else:
                await info.storage.delete_one(
                    "members",
                    {
                        "account": encode_int_as_bytes(mbe.account),
                        "guild": encode_int_as_bytes(mbe.guild),
                        "token_id": encode_int_as_bytes(mbe.id),
                    },
                )
        elif event.name == "MemberRoleUpdated":
            mrue = decode_member_role_updated_event(event.data)
            member_role_updated_docs = {
                "account": encode_int_as_bytes(mrue.account),
                "role": encode_int_as_bytes(mrue.role),
            }
            await info.storage.find_one_and_update(
                "members",
                member_role_updated_docs.pop("role"),
                member_role_updated_docs,
            )
        elif event.name == "PermissionsSet":
            pse = decode_permissions_set_event(event.data)
            permissions_set_doc = {
                "guild": event.address,
                "account": encode_int_as_bytes(pse.account),
                "permissions": encode_permissions_as_bytes(pse.permissions),
                "timestamp": block_time,
            }

            await info.storage.insert_one("permissions", permissions_set_doc)
        elif event.name == "TransactionExecuted":
            te = decode_transaction_executed_event(event.data)
            transaction_executed_doc = {
                "account": encode_int_as_bytes(te.account),
                "hash": encode_int_as_bytes(te.hash),
                "response": encode_int_as_bytes(te.response),
            }
            await info.storage.insert_one("transactions", transaction_executed_doc)
        elif event.name in ["Deposited", "Withdrawn"]:
            dwe = decode_deposit_withdraw_event(event.data)
            deposit_withdraw_doc = {
                "account": encode_int_as_bytes(dwe.account),
                "certificate_id": encode_int_as_bytes(dwe.certificate_id),
                "guild": event.address,
                "token_standard": encode_int_as_bytes(dwe.token_standard),
                "token": encode_int_as_bytes(dwe.token),
                "token_id": encode_int_as_bytes(dwe.token_id),
                "amount": encode_int_as_bytes(dwe.amount),
            }
            filter = {
                "account": encode_int_as_bytes(dwe.account),
                "certificate_id": encode_int_as_bytes(dwe.certificate_id),
                "token_standard": encode_int_as_bytes(dwe.token_standard),
                "token": encode_int_as_bytes(dwe.token),
                "token_id": encode_int_as_bytes(dwe.token_id),
            }
            if event.name == "Deposited":
                token = await info.storage.find_one("tokens", filter)
                if token:
                    deposit_withdraw_doc["amount"] = (
                        deposit_withdraw_doc["amount"] + token.amount
                    )
                    await info.storage.find_one_and_update(
                        "tokens",
                        filter,
                        deposit_withdraw_doc,
                    )
                else:
                    await info.storage.insert_one("tokens", deposit_withdraw_doc)
            if event.name == "Withdrawn":
                token = await info.storage.find_one("tokens", filter)
                if token:
                    deposit_withdraw_doc["amount"] = (
                        deposit_withdraw_doc["amount"] - token.amount
                    )
                    if deposit_withdraw_doc["amount"] == 0:
                        await info.storage.delete_one("tokens", filter)
                    else:
                        await info.storage.find_one_and_update(
                            "tokens",
                            filter,
                            deposit_withdraw_doc,
                        )
                else:
                    print("error: withdraw of undeposited token")
        else:
            print("error: event", event.name, "not supported")

    # new_token_owner = dict()
    # for transfer in transfers:
    #     new_token_owner[transfer.token_id] = transfer.to_address

    # for token_id, new_member in new_token_owner.items():
    #     token_id = encode_int_as_bytes(token_id)
    #     await info.storage.find_one_and_replace(
    #         "tokens",
    #         {"token_id": token_id},
    #         {
    #             "token_id": token_id,
    #             "owner": encode_int_as_bytes(new_owner),
    #             "updated_at": block_time,
    #         },
    #         upsert=True,
    #     )


async def handle_block(info: Info, block: NewBlock):
    """Handle a new _live_ block."""
    print(block.new_head)


async def run_indexer(server_url=None, mongo_url=None, restart=None):
    print("Starting Apibara indexer")
    # if mongo_url is None:
    #     mongo_url = "mongodb://apibara:apibara@localhost:27017"

    # if restart:
    #     async with Client.connect(server_url) as client:
    #         existing = await client.indexer_client().get_indexer(indexer_id)
    #         if existing:
    #             await client.indexer_client().delete_indexer(indexer_id)

    #         # Delete old database entries.
    #         # Notice that apibara maps indexer ids to database names by
    #         # doing `indexer_id.replace('-', '_')`.
    #         # In the future all data will be handled by Apibara and this step
    #         # will not be necessary.
    #         mongo = MongoClient(mongo_url)
    #         mongo.drop_database(indexer_id.replace("-", "_"))

    runner = IndexerRunner(
        config=IndexerRunnerConfiguration(
            apibara_url=server_url,
            apibara_ssl=True,
            storage_url=mongo_url,
        ),
        reset_state=restart,
        indexer_id=indexer_id,
        new_events_handler=handle_events,
    )

    # runner.add_block_handler(handle_block)

    # Create the indexer if it doesn't exist on the server,
    # otherwise it will resume indexing from where it left off.
    #
    # For now, this also helps the SDK map between human-readable
    # event names and StarkNet events.
    runner.add_event_filters(
        filters=[
            EventFilter.from_event_name(
                name="GuildContractDeployed",
                address="0x0145806a98aa73f1fea42756840717f3d02732760c1bc91a8f5c118290b9474e",
            ),
            EventFilter.from_event_name(
                name="MintCertificate",
                address="0x04b8badf02826a7be3a171ce6074b4ec1f6a1c328fb62009e6217896557a08bf",
            ),
            EventFilter.from_event_name(
                name="BurnCertificate",
                address="0x04b8badf02826a7be3a171ce6074b4ec1f6a1c328fb62009e6217896557a08bf",
            ),
        ],
        index_from_block=360_000,
    )

    print("Initialization completed. Entering main loop.")

    await runner.run()
