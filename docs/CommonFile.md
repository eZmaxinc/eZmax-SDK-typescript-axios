# CommonFile

Object representing a file used in a request or response context 

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sFileName** | **string** | The name of the file | [default to undefined]
**sFileUrl** | **string** | The URL used to reach the File | [optional] [default to undefined]
**sFileBase64** | **string** | The Base64 encoded binary content of the File | [optional] [default to undefined]
**eFileSource** | **string** | The source of the File | [default to undefined]

## Example

```typescript
import { CommonFile } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonFile = {
    sFileName,
    sFileUrl,
    sFileBase64,
    eFileSource,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
