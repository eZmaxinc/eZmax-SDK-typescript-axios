# BankaccountImportIntoEDMV1Response

Response for POST /1/object/bankaccount/{pkiBankaccountID}/importIntoEDM

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**BankaccountImportIntoEDMV1ResponseMPayload**](BankaccountImportIntoEDMV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { BankaccountImportIntoEDMV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BankaccountImportIntoEDMV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
