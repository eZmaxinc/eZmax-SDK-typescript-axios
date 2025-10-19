# EzsigntemplatedocumentRequestCompound

A Ezsigntemplatedocument Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatedocumentID** | **number** | The unique ID of the Ezsigntemplatedocument | [optional] [default to undefined]
**fkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [default to undefined]
**fkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [optional] [default to undefined]
**fkiEzsigntemplatesignerID** | **number** | The unique ID of the Ezsigntemplatesigner | [optional] [default to undefined]
**sEzsigntemplatedocumentName** | **string** | The name of the Ezsigntemplatedocument. | [default to undefined]
**eEzsigntemplatedocumentSource** | **string** | Indicates where to look for the document binary content. | [default to undefined]
**eEzsigntemplatedocumentFormat** | **string** | Indicates the format of the template. | [optional] [default to undefined]
**sEzsigntemplatedocumentBase64** | **string** | The Base64 encoded binary content of the document.  This field is Required when eEzsigntemplatedocumentSource &#x3D; Base64. | [optional] [default to undefined]
**sEzsigntemplatedocumentUrl** | **string** | The url where the document content resides.  This field is Required when eEzsigntemplatedocumentSource &#x3D; Url. | [optional] [default to undefined]
**bEzsigntemplatedocumentForcerepair** | **boolean** | Try to repair the document or flatten it if it cannot be used for electronic signature. | [optional] [default to undefined]
**eEzsigntemplatedocumentForm** | **string** | If the document contains an existing PDF form this property must be set.  **Keep** leaves the form as-is in the document.  **Convert** removes the form and convert all the existing fields to Ezsigntemplateformfieldgroups and assign them to the specified **fkiEzsigntemplatesignerID**  **Discard** removes the form from the document  **Flatten** prints the form values in the document. | [optional] [default to undefined]
**sEzsigntemplatedocumentPassword** | **string** | If the source template is password protected, the password to open/modify it. | [optional] [default to '']

## Example

```typescript
import { EzsigntemplatedocumentRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatedocumentRequestCompound = {
    pkiEzsigntemplatedocumentID,
    fkiEzsigntemplateID,
    fkiEzsigndocumentID,
    fkiEzsigntemplatesignerID,
    sEzsigntemplatedocumentName,
    eEzsigntemplatedocumentSource,
    eEzsigntemplatedocumentFormat,
    sEzsigntemplatedocumentBase64,
    sEzsigntemplatedocumentUrl,
    bEzsigntemplatedocumentForcerepair,
    eEzsigntemplatedocumentForm,
    sEzsigntemplatedocumentPassword,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
