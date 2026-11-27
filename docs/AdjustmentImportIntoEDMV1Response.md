# AdjustmentImportIntoEDMV1Response

Response for POST /1/object/adjustment/{pkiAdjustmentID}/importIntoEDM

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**AdjustmentImportIntoEDMV1ResponseMPayload**](AdjustmentImportIntoEDMV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { AdjustmentImportIntoEDMV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AdjustmentImportIntoEDMV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
