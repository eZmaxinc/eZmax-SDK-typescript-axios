# CustomEzmaxinvoicingEzsigndocumentResponse

An EzmaxinvoicingEzsigndocument object containing information about the Ezmaxinvoicing for an Ezsigndocument

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**fkiBillingentityinternalID** | **number** | The unique ID of the Billingentityinternal. | [optional] [default to undefined]
**sName** | **string** |  | [default to undefined]
**sEzsignfolderDescription** | **string** | The description of the Ezsignfolder | [default to undefined]
**sEzsigndocumentName** | **string** | The name of the document that will be presented to Ezsignfoldersignerassociations | [default to undefined]
**bEzsignfolderAllowed** | **boolean** | Whether you have access to the Ezsignfolder or not | [default to undefined]

## Example

```typescript
import { CustomEzmaxinvoicingEzsigndocumentResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzmaxinvoicingEzsigndocumentResponse = {
    fkiEzsignfolderID,
    fkiBillingentityinternalID,
    sName,
    sEzsignfolderDescription,
    sEzsigndocumentName,
    bEzsignfolderAllowed,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
