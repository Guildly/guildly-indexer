import asyncio
from datetime import datetime
from sqlite3 import Date, Timestamp
from time import time
from typing import List, NewType, Optional, Dict
from xmlrpc.client import DateTime
from pyrsistent import optional

import strawberry
from aiohttp import web
from pymongo import MongoClient
from strawberry.aiohttp.views import GraphQLView
from indexer.indexer import indexer_id
from indexer.utils import felt_to_str, str_to_felt


def parse_hex(value):
    if not value.startswith("0x"):
        raise valueError("invalid Hex value")
    return bytes.fromhex(value.replace("0x", ""))

def serialize_hex(token_id):
    return "0x" + token_id.hex()

def parse_felt(value):
    return value.to_bytes(32, "big")

def serialize_felt(value):
    return int.from_bytes(value, "big")

def parse_string(value):
    felt = str_to_felt(value)
    return felt.to_bytes(32, "big")

def serialize_string(value):
    felt = int.from_bytes(value, "big")
    return felt_to_str(felt)

def parse_permission(value):
    to = value["to"]
    selector = value["selector"]
    to_bytes = to.to_bytes(32, "big")
    selector_bytes = selector.to_bytes(32, "big")
    return {"to": to_bytes, "selector": selector_bytes}

def serialize_permission(value):
    to = value["to"]
    selector = value["selector"]
    to_felt = int.from_bytes(to, "big")
    selector_felt = int.from_bytes(selector, "big")
    return {"to": to_felt, "selector": selector_felt}


HexValue = strawberry.scalar(
    NewType("HexValue", bytes), parse_value=parse_hex, serialize=serialize_hex
)

FeltValue = strawberry.scalar(
    NewType("FeltValue", bytes), parse_value=parse_felt, serialize=serialize_felt
)

StringValue = strawberry.scalar(
    NewType("StringValue", bytes), parse_value=parse_string, serialize=serialize_string
)

PermissionValue = strawberry.scalar(
    NewType("PermissionValue", bytes), parse_value=parse_permission, serialize=serialize_permission
)



@strawberry.input
class StringFilter:
    eq: Optional[StringValue] = None
    _in: Optional[List[StringValue]] = None
    notIn: Optional[StringValue] = None
    lt: Optional[StringValue] = None
    lte: Optional[StringValue] = None
    gt: Optional[StringValue] = None
    gte: Optional[StringValue] = None
    contains: Optional[StringValue] = None
    startsWith: Optional[StringValue] = None
    endsWith: Optional[StringValue] = None

@strawberry.input
class HexValueFilter:
  eq: Optional[HexValue] = None
  _in: Optional[List[HexValue]] = None
  notIn: Optional[List[HexValue]] = None
  lt: Optional[HexValue] = None
  lte: Optional[HexValue] = None
  gt: Optional[HexValue] = None
  gte: Optional[HexValue] = None

@strawberry.input
class FeltValueFilter:
  eq: Optional[FeltValue] = None
  _in: Optional[List[FeltValue]] = None
  notIn: Optional[List[FeltValue]] = None
  lt: Optional[FeltValue] = None
  lte: Optional[FeltValue] = None
  gt: Optional[FeltValue] = None
  gte: Optional[FeltValue] = None

@strawberry.input
class DateTimeFilter:
  eq: Optional[datetime] = None
  _in: Optional[List[datetime]] = None
  notIn: Optional[List[datetime]] = None
  lt: Optional[datetime] = None
  lte: Optional[datetime] = None
  gt: Optional[datetime] = None
  gte: Optional[datetime] = None

@strawberry.input
class OrderByInput:
    asc: Optional[bool] = False
    desc: Optional[bool] = False

@strawberry.input
class GuildsOrderByInput:
    name: Optional[OrderByInput] = None
    master: Optional[OrderByInput] = None
    address: Optional[OrderByInput] = None
    timestamp: Optional[OrderByInput] = None

@strawberry.input
class MembersOrderByInput:
    account: Optional[OrderByInput] = None
    role: Optional[OrderByInput] = None
    guild: Optional[OrderByInput] = None
    token_id: Optional[OrderByInput] = None
    timestamp: Optional[OrderByInput] = None

@strawberry.input
class PermissionsOrderByInput:
    guild: Optional[OrderByInput] = None
    account: Optional[OrderByInput] = None
    permissions: Optional[OrderByInput] = None
    timestamp: Optional[OrderByInput] = None

@strawberry.input
class TokensOrderByInput:
    account: Optional[OrderByInput] = None
    certificate_id: Optional[OrderByInput] = None
    guild: Optional[OrderByInput] = None
    token_standard: Optional[OrderByInput] = None
    token: Optional[OrderByInput] = None
    token_id: Optional[OrderByInput] = None
    amount: Optional[OrderByInput] = None

@strawberry.input
class TransactionsOrderByInput:
    account: Optional[OrderByInput] = None
    hash: Optional[OrderByInput] = None
    response: Optional[OrderByInput] = None

@strawberry.input
class GuildsFilter:
    name: Optional[StringFilter] = None
    master: Optional[HexValueFilter] = None
    address: Optional[HexValueFilter] = None
    timestamp: Optional[DateTimeFilter] = None

@strawberry.input
class MembersFilter:
    account: Optional[HexValueFilter] = None
    role: Optional[FeltValueFilter] = None
    guild: Optional[HexValueFilter] = None
    token_id: Optional[FeltValueFilter] = None
    timestamp: Optional[DateTimeFilter] = None

@strawberry.input
class PermissionsFilter:
    guild: Optional[HexValueFilter] = None
    account: Optional[HexValueFilter] = None
    permissions: Optional[HexValueFilter] = None
    timestamp: Optional[DateTimeFilter] = None

@strawberry.input
class TokensFilter:
    account: Optional[HexValueFilter] = None
    certificate_id: Optional[FeltValueFilter] = None
    guild: Optional[HexValueFilter] = None
    token_standard: Optional[FeltValueFilter] = None
    token: Optional[HexValueFilter] = None
    token_id: Optional[FeltValueFilter] = None
    amount: Optional[FeltValueFilter] = None

@strawberry.input
class TransactionsFilter:
    account: Optional[HexValueFilter] = None
    hash: Optional[HexValueFilter] = None
    response: Optional[List[HexValueFilter]] = None

@strawberry.type
class Guild:
    name: StringValue
    master: HexValue
    address: HexValue
    timestamp: datetime

    @classmethod
    def from_mongo(cls, data):
        return cls(
            name=data["name"],
            master=data["master"],
            address=data["address"],
            timestamp=data["timestamp"],
        )


@strawberry.type
class Member:
    account: HexValue
    role: FeltValue
    guild: HexValue
    token_id: FeltValue
    timestamp: datetime

    @classmethod
    def from_mongo(cls, data):
        return cls(
            account=data["account"],
            role=data["role"],
            guild=data["guild"],
            token_id=data["token_id"],
            timestamp=data["timestamp"],
        )

@strawberry.type
class Permissions:
    guild: HexValue
    account: HexValue
    permissions: List[PermissionValue]
    timestamp: datetime

    @classmethod
    def from_mongo(cls, data):
        return cls(
            guild=data["guild"],
            account=data["account"],
            permissions=data["permissions"],
            timestamp=data["timestamp"]
        )


@strawberry.type
class Token:
    account: HexValue
    certificate_id: FeltValue
    guild: HexValue
    token_standard: FeltValue
    token: HexValue
    token_id: FeltValue
    amount: FeltValue

    @classmethod
    def from_mongo(cls, data):
        return cls(
            account=data["account"],
            certificate_id=data["certificate_id"],
            guild=data["guild"],
            token_standard=data["token_standard"],
            token=data["token"],
            token_id=data["token_id"],
            amount=data["amount"],
        )


@strawberry.type
class Transaction:
    account: HexValue
    hash: HexValue
    response: List[HexValue]

    @classmethod
    def from_mongo(cls, data):
        return cls(
            account=data["account"], hash=data["hash"], response=data["response"]
        )


# @strawberry.type
# class Token:
#     token_id: HexValue
#     owner: HexValue
#     updated_at: datetime

#     @classmethod
#     def from_mongo(cls, data):
#         return cls(
#             token_id=data["token_id"],
#             owner=data["owner"],
#             updated_at=data["updated_at"],
#         )

#     @strawberry.field
#     def transfers(self, info, limit: int = 10, skip: int = 0) -> List[Transfer]:
#         db = info.context["db"]
#         query = (
#             db["transfers"]
#             .find({"token_id": self.token_id})
#             .limit(limit)
#             .skip(skip)
#             .sort("timestamp", -1)
#         )

#         return [Transfer.from_mongo(t) for t in query]

def get_str_filters(
    where: StringFilter
) -> List[Dict]:
    filter = {}
    if where.eq:
        filter = where.eq
    if where._in:
        filter["$in"] = where._in
    if where.notIn:
        filter["$nin"] = where.notIn
    if where.lt:
        filter["$lt"] = where.lt
    if where.lte:
        filter["$lte"] = where.lte
    if where.gt:
        filter["$gt"] = where.gt
    if where.gte:
        filter["$gte"] = where.gte
    if where.contains:
        filter["$regex"] = where.contains
    if where.startsWith:
        filter["$regex"] = "^" + where.startsWith
    if where.endsWith:
        filter["$regex"] = where.endsWith + "$"

    return filter

def get_felt_filters(
    where: FeltValueFilter
) -> List[Dict]:
    filter = {}
    if where.eq:
        filter = where.eq
    if where._in:
        filter["$in"] = where._in
    if where.notIn:
        filter["$nin"] = where.notIn
    if where.lt:
        filter["$lt"] = where.lt
    if where.lte:
        filter["$lte"] = where.lte
    if where.gt:
        filter["$gt"] = where.gt
    if where.gte:
        filter["$gte"] = where.gte

    return filter

def get_hex_filters(
    where: HexValueFilter
) -> List[Dict]:
    filter = {}
    if where.eq:
        filter = where.eq
    if where._in:
        filter["$in"] = where._in
    if where.notIn:
        filter["$nin"] = where.notIn
    if where.lt:
        filter["$lt"] = where.lt
    if where.lte:
        filter["$lte"] = where.lte
    if where.gt:
        filter["$gt"] = where.gt
    if where.gte:
        filter["$gte"] = where.gte

    return filter

def get_date_filters(
    where: DateTimeFilter
) -> List[Dict]:
    filter = {}
    if where.eq:
        filter = where.eq
    if where._in:
        filter["$in"] = where._in
    if where.notIn:
        filter["$nin"] = where.notIn
    if where.lt:
        filter["$lt"] = where.lt
    if where.lte:
        filter["$lte"] = where.lte
    if where.gt:
        filter["$gt"] = where.gt
    if where.gte:
        filter["$gte"] = where.gte

    return filter


def get_guilds(
    info,
    where: Optional[GuildsFilter] = {},
    limit: Optional[int] = 10,
    skip: Optional[int] = 0,
    orderBy: Optional[GuildsOrderByInput] = {}
) -> List[Guild]:
    db = info.context["db"]

    filter = {"_chain.valid_to": None}
    if where.name is not None:
        filter["name"] = get_str_filters(where.name)
    if where.master is not None:
        filter["master"] = get_hex_filters(where.master)
    if where.address is not None:
        filter["address"] = get_hex_filters(where.address)
    if where.timestamp is not None:
        filter["timestamp"] = get_date_filters(where.timestamp)

    if orderBy.name is not None:
        if orderBy.name.asc:
            sort_var = "name"
            sort_dir = 1
        if orderBy.name.desc:
            sort_var = "name"
            sort_dir = -1
    if orderBy.master is not None:
        if orderBy.master.asc:
            sort_var = "master"
            sort_dir = 1
        if orderBy.master.desc:
            sort_var = "master"
            sort_dir = -1
    if orderBy.address is not None:
        if orderBy.address.asc:
            sort_var = "address"
            sort_dir = 1
        if orderBy.address.desc:
            sort_var = "address"
            sort_dir = -1
    if orderBy.timestamp is not None:
        if orderBy.timestamp.asc:
            sort_var = "timestamp"
            sort_dir = 1
        if orderBy.timestamp.desc:
            sort_var = "timestamp"
            sort_dir = -1
    else:
        sort_var = "updated_at"
        sort_dir = -1

    query = db["guilds"].find(filter).skip(skip).limit(limit).sort(sort_var, sort_dir)

    return [Guild.from_mongo(t) for t in query]

def get_members(
    info, where: Optional[MembersFilter] = {}, limit: int = 10, skip: int = 0, orderBy: Optional[MembersOrderByInput] = {"var": "updated_at"}
) -> List[Member]:
    db = info.context["db"]

    filter = {"_chain.valid_to": None}
    if where.account is not None:
        filter["account"] = get_hex_filters(where.account)
    if where.role is not None:
        filter["role"] = get_felt_filters(where.role)
    if where.guild is not None:
        filter["guild"] = get_hex_filters(where.guild)
    if where.token_id is not None:
        filter["token_id"] = get_felt_filters(where.token_id)
    if where.timestamp is not None:
        filter["timestamp"] = get_date_filters(where.timestamp)

    if orderBy.account is not None:
        if orderBy.account.asc:
            sort_var = "account"
            sort_dir = 1
        if orderBy.account.desc:
            sort_var = "account"
            sort_dir = -1
    if orderBy.role is not None:
        if orderBy.role.asc:
            sort_var = "role"
            sort_dir = 1
        if orderBy.rike.desc:
            sort_var = "role"
            sort_dir = -1
    if orderBy.guild is not None:
        if orderBy.guild.asc:
            sort_var = "guild"
            sort_dir = 1
        if orderBy.guild.desc:
            sort_var = "guild"
            sort_dir = -1
    if orderBy.token_id is not None:
        if orderBy.token_id.asc:
            sort_var = "token_id"
            sort_dir = 1
        if orderBy.token_id.desc:
            sort_var = "token_id"
            sort_dir = -1
    if orderBy.timestamp is not None:
        if orderBy.timestamp.asc:
            sort_var = "timestamp"
            sort_dir = 1
        if orderBy.timestamp.desc:
            sort_var = "timestamp"
            sort_dir = -1
    else:
        sort_var = "updated_at"
        sort_dir = -1

    query = db["members"].find(filter).skip(skip).limit(limit).sort(sort_var, sort_dir)

    return [Member.from_mongo(t) for t in query]

def get_permissions(
    info, where: Optional[PermissionsFilter] = {}, limit: int = 10, skip: int = 0, orderBy: Optional[PermissionsOrderByInput] = {"var": "updated_at"}
) -> List[Permissions]:
    db = info.context["db"]

    filter = {"_chain.valid_to": None}
    if where.guild is not None:
        filter["guild"] = get_hex_filters(where.guild)
    if where.account is not None:
        filter["account"] = get_hex_filters(where.account)
    if where.timestamp is not None:
        filter["timestamp"] = get_date_filters(where.timestamp)

    if orderBy.guild is not None:
        if orderBy.guild.asc:
            sort_var = "guild"
            sort_dir = 1
        if orderBy.guild.desc:
            sort_var = "guild"
            sort_dir = -1
    if orderBy.account is not None:
        if orderBy.account.asc:
            sort_var = "account"
            sort_dir = 1
        if orderBy.account.desc:
            sort_var = "account"
            sort_dir = -1
    if orderBy.timestamp is not None:
        if orderBy.timestamp.asc:
            sort_var = "timestamp"
            sort_dir = 1
        if orderBy.timestamp.desc:
            sort_var = "timestamp"
            sort_dir = -1
    else:
        sort_var = "updated_at"
        sort_dir = -1

    query = db["permissions"].find(filter).skip(skip).limit(limit).sort(sort_var, sort_dir)

    return [Permissions.from_mongo(t) for t in query]


def get_tokens(
    info, where: Optional[TokensFilter] = {}, limit: int = 10, skip: int = 0, orderBy: Optional[TokensOrderByInput] = {"var": "updated_at"}
) -> List[Token]:
    db = info.context["db"]

    filter = {"_chain.valid_to": None}
    if where.account is not None:
        filter["account"] = get_hex_filters(where.account)
    if where.certificate_id is not None:
        filter["certificate_id"] = get_felt_filters(where.certificate_id)
    if where.guild is not None:
        filter["guild"] = get_hex_filters(where.guild)
    if where.token_standard is not None:
        filter["token_standard"] = get_felt_filters(where.token_standard)
    if where.token is not None:
        filter["token"] = get_hex_filters(where.token)
    if where.token_id is not None:
        filter["token_id"] = get_felt_filters(where.token_id)
    if where.amount is not None:
        filter["amount"] = get_felt_filters(where.amount)

    if orderBy.account is not None:
        if orderBy.account.asc:
            sort_var = "account"
            sort_dir = 1
        if orderBy.account.desc:
            sort_var = "account"
            sort_dir = -1
    if orderBy.certificate_id is not None:
        if orderBy.certificate_id.asc:
            sort_var = "certificate_id"
            sort_dir = 1
        if orderBy.rike.desc:
            sort_var = "role"
            sort_dir = -1
    if orderBy.guild is not None:
        if orderBy.guild.asc:
            sort_var = "guild"
            sort_dir = 1
        if orderBy.guild.desc:
            sort_var = "guild"
            sort_dir = -1
    if orderBy.token_standard is not None:
        if orderBy.token_standard.asc:
            sort_var = "token_standard"
            sort_dir = 1
        if orderBy.token_standard.desc:
            sort_var = "token_standard"
            sort_dir = -1
    if orderBy.token is not None:
        if orderBy.token.asc:
            sort_var = "token"
            sort_dir = 1
        if orderBy.token.desc:
            sort_var = "token"
            sort_dir = -1
    if orderBy.token_id is not None:
        if orderBy.token_id.asc:
            sort_var = "token_id"
            sort_dir = 1
        if orderBy.token_id.desc:
            sort_var = "token_id"
            sort_dir = -1
    if orderBy.amount is not None:
        if orderBy.amount.asc:
            sort_var = "amount"
            sort_dir = 1
        if orderBy.amount.desc:
            sort_var = "amount"
            sort_dir = -1
    else:
        sort_var = "updated_at"
        sort_dir = -1
        

    query = db["tokens"].find(filter).skip(skip).limit(limit).sort(sort_var, sort_dir)

    return [Token.from_mongo(t) for t in query]


def get_transactions(
    info, where: Optional[TransactionsFilter] = None, limit: int = 10, skip: int = 0, orderBy: Optional[TransactionsOrderByInput] = {"var": "updated_at"}
) -> List[Transaction]:
    db = info.context["db"]

    filter = {"_chain.valid_to": None}
    if where.account is not None:
        filter["account"] = get_hex_filters(where.account)
    if where.hash is not None:
        filter["hash"] = get_hex_filters(where.hash)
    if where.response is not None:
        filter["response"] = get_hex_filters(where.response)

    if orderBy.account is not None:
        if orderBy.account.asc:
            sort_var = "account"
            sort_dir = 1
        if orderBy.account.desc:
            sort_var = "account"
            sort_dir = -1
    if orderBy.hash is not None:
        if orderBy.hash.asc:
            sort_var = "hash"
            sort_dir = 1
        if orderBy.hash.desc:
            sort_var = "hash"
            sort_dir = -1
    if orderBy.response is not None:
        if orderBy.response.asc:
            sort_var = "response"
            sort_dir = 1
        if orderBy.response.desc:
            sort_var = "response"
            sort_dir = -1
    else:
        sort_var = "updated_at"
        sort_dir = -1

    query = (
        db["transactions"].find(filter).skip(skip).limit(limit).sort(sort_var, sort_dir)
    )

    return [Transaction.from_mongo(t) for t in query]


@strawberry.type
class Query:
    guilds: List[Guild] = strawberry.field(resolver=get_guilds)
    members: List[Member] = strawberry.field(resolver=get_members)
    permissions: List[Permissions] = strawberry.field(resolver=get_permissions)
    tokens: List[Token] = strawberry.field(resolver=get_tokens)
    transactions: List[Transaction] = strawberry.field(resolver=get_transactions)


class IndexerGraphQLView(GraphQLView):
    def __init__(self, db, **kwargs):
        super().__init__(**kwargs)
        self._db = db

    async def get_context(self, _request, _response):
        return {"db": self._db}


async def run_graphql_api(mongo_url=None):
    if mongo_url is None:
        mongo_url = "mongodb://apibara:apibara@localhost:27017"

    mongo = MongoClient(mongo_url)
    db_name = indexer_id.replace("-", "_")
    db = mongo[db_name]

    schema = strawberry.Schema(query=Query)
    view = IndexerGraphQLView(db, schema=schema)

    app = web.Application()
    app.router.add_route("*", "/graphql", view)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", "8080")
    await site.start()

    print(f"GraphQL server started on port 8080")

    while True:
        await asyncio.sleep(5_000)
