# EzdoctemplatedocumentRequestPatch

An Ezdoctemplatedocument Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eEzdoctemplatedocumentFormat** | **string** | Indicates the format of the template.  This field is Required when sEzdoctemplatedocumentBase64 is set. | [optional] [default to undefined]
**sEzdoctemplatedocumentFields** | **string** | List of field in Ezdoctemplatedocument | [optional] [default to undefined]
**sEzdoctemplatedocumentBase64** | **string** | The Base64 encoded binary content of the document.  This field is Required when eEzdoctemplatedocumentFormat is set. | [optional] [default to undefined]

## Example

```typescript
import { EzdoctemplatedocumentRequestPatch } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzdoctemplatedocumentRequestPatch = {
    eEzdoctemplatedocumentFormat,
    sEzdoctemplatedocumentFields,
    sEzdoctemplatedocumentBase64,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
