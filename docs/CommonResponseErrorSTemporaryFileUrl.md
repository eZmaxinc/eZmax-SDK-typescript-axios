# CommonResponseErrorSTemporaryFileUrl

Generic Error Message

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sErrorMessage** | **string** | The message giving details about the error | [default to undefined]
**eErrorCode** | [**FieldEErrorCode**](FieldEErrorCode.md) |  | [default to undefined]
**a_sErrorMessagedetail** | **Array&lt;string&gt;** | More error message detail | [optional] [default to undefined]
**sTemporaryFileUrl** | **string** | The Temporary File Url of the document that was uploaded. That url can be reused instead of uploading the file again. | [optional] [default to undefined]

## Example

```typescript
import { CommonResponseErrorSTemporaryFileUrl } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonResponseErrorSTemporaryFileUrl = {
    sErrorMessage,
    eErrorCode,
    a_sErrorMessagedetail,
    sTemporaryFileUrl,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
