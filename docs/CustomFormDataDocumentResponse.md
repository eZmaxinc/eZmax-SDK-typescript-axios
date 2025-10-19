# CustomFormDataDocumentResponse

A form Data Document Object 

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [default to undefined]
**fkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**sEzsigndocumentName** | **string** | The name of the document that will be presented to Ezsignfoldersignerassociations | [default to undefined]
**dtModifiedDate** | **string** | The date and time at which the object was last modified | [default to undefined]
**a_objFormDataSigner** | [**Array&lt;CustomFormDataSignerResponse&gt;**](CustomFormDataSignerResponse.md) |  | [default to undefined]

## Example

```typescript
import { CustomFormDataDocumentResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomFormDataDocumentResponse = {
    pkiEzsigndocumentID,
    fkiEzsignfolderID,
    sEzsigndocumentName,
    dtModifiedDate,
    a_objFormDataSigner,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
