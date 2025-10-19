# BrokerGetListV1Response

Response for GET /1/object/broker/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayloadGetList**](CommonResponseObjDebugPayloadGetList.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**BrokerGetListV1ResponseMPayload**](BrokerGetListV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { BrokerGetListV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BrokerGetListV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
