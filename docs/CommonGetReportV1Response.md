# CommonGetReportV1Response

Response for POST /1/report/xxx/xxx and /1/module/report/getReportFromCache

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**CommonGetReportV1ResponseMPayload**](CommonGetReportV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { CommonGetReportV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonGetReportV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
