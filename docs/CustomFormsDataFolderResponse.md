# CustomFormsDataFolderResponse

A forms Data Folder Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**sEzsignfolderDescription** | **string** | The description of the Ezsignfolder | [default to undefined]
**a_objFormDataDocument** | [**Array&lt;CustomFormDataDocumentResponse&gt;**](CustomFormDataDocumentResponse.md) |  | [default to undefined]

## Example

```typescript
import { CustomFormsDataFolderResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomFormsDataFolderResponse = {
    pkiEzsignfolderID,
    sEzsignfolderDescription,
    a_objFormDataDocument,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
