# CommissionadvanceImportIntoEDMV1Response

Response for POST /1/object/commissionadvance/{pkiCommissionadvanceID}/importIntoEDM

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**CommissionadvanceImportIntoEDMV1ResponseMPayload**](CommissionadvanceImportIntoEDMV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { CommissionadvanceImportIntoEDMV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommissionadvanceImportIntoEDMV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
