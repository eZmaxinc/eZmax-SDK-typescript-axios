# EzsigndocumentRequestCompound

An Ezsigndocument Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [optional] [default to undefined]
**fkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**fkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [optional] [default to undefined]
**fkiEzsignfoldersignerassociationID** | **number** | The unique ID of the Ezsignfoldersignerassociation | [optional] [default to undefined]
**fkiEzsignimportdocumentID** | **number** | The unique ID of the Ezsignimportdocument | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**eEzsigndocumentSource** | **string** | Indicates where to look for the document binary content. | [default to undefined]
**eEzsigndocumentFormat** | **string** | Indicates the format of the document. | [optional] [default to undefined]
**sEzsigndocumentBase64** | **string** | The Base64 encoded binary content of the document.  This field is Required when eEzsigndocumentSource &#x3D; Base64. | [optional] [default to undefined]
**sEzsigndocumentUrl** | **string** | The url where the document content resides.  This field is Required when eEzsigndocumentSource &#x3D; Url. | [optional] [default to undefined]
**bEzsigndocumentForcerepair** | **boolean** | Try to repair the document or flatten it if it cannot be used for electronic signature.  | [optional] [default to true]
**sEzsigndocumentPassword** | **string** | If the source document is password protected, the password to open/modify it. | [optional] [default to undefined]
**eEzsigndocumentForm** | **string** | If the document contains an existing PDF form this property must be set.  **Keep** leaves the form as-is in the document.  **Convert** removes the form and convert all the existing fields to Ezsignformfieldgroups and assign them to the specified **fkiEzsignfoldersignerassociationID**  **Discard** removes the form from the document.  **Flatten** prints the form values in the document. | [optional] [default to undefined]
**dtEzsigndocumentDuedate** | **string** | The maximum date and time at which the Ezsigndocument can be signed. | [optional] [default to undefined]
**sEzsigndocumentName** | **string** | The name of the document that will be presented to Ezsignfoldersignerassociations | [default to undefined]
**sEzsigndocumentExternalid** | **string** | This field can be used to store an External ID from the client\&#39;s system.  Anything can be stored in this field, it will never be evaluated by the eZmax system and will be returned AS-IS.  To store multiple values, consider using a JSON formatted structure, a URL encoded string, a CSV or any other custom format.  | [optional] [default to undefined]

## Example

```typescript
import { EzsigndocumentRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentRequestCompound = {
    pkiEzsigndocumentID,
    fkiEzsignfolderID,
    fkiEzsigntemplateID,
    fkiEzsignfoldersignerassociationID,
    fkiEzsignimportdocumentID,
    fkiLanguageID,
    eEzsigndocumentSource,
    eEzsigndocumentFormat,
    sEzsigndocumentBase64,
    sEzsigndocumentUrl,
    bEzsigndocumentForcerepair,
    sEzsigndocumentPassword,
    eEzsigndocumentForm,
    dtEzsigndocumentDuedate,
    sEzsigndocumentName,
    sEzsigndocumentExternalid,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
