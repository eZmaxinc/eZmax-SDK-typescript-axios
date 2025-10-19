# SubnetGetObjectV2Response

Response for GET /2/object/subnet/{pkiSubnetID}

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**SubnetGetObjectV2ResponseMPayload**](SubnetGetObjectV2ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { SubnetGetObjectV2Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SubnetGetObjectV2Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
