# EzsigntemplatepackagesignerRequestCompound

A Ezsigntemplatepackagesigner Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatepackagesignerID** | **number** | The unique ID of the Ezsigntemplatepackagesigner | [optional] [default to undefined]
**fkiEzsigntemplatepackageID** | **number** | The unique ID of the Ezsigntemplatepackage | [default to undefined]
**fkiEzdoctemplatedocumentID** | **number** | The unique ID of the Ezdoctemplatedocument | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiUsergroupID** | **number** | The unique ID of the Usergroup | [optional] [default to undefined]
**bEzsigntemplatepackagesignerReceivecopy** | **boolean** | If this flag is true. The signatory will receive a copy of every signed Ezsigndocument even if it ain\&#39;t required to sign the document. | [optional] [default to undefined]
**eEzsigntemplatepackagesignerMapping** | [**FieldEEzsigntemplatepackagesignerMapping**](FieldEEzsigntemplatepackagesignerMapping.md) |  | [optional] [default to undefined]
**sEzsigntemplatepackagesignerDescription** | **string** | The description of the Ezsigntemplatepackagesigner | [default to undefined]

## Example

```typescript
import { EzsigntemplatepackagesignerRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatepackagesignerRequestCompound = {
    pkiEzsigntemplatepackagesignerID,
    fkiEzsigntemplatepackageID,
    fkiEzdoctemplatedocumentID,
    fkiUserID,
    fkiUsergroupID,
    bEzsigntemplatepackagesignerReceivecopy,
    eEzsigntemplatepackagesignerMapping,
    sEzsigntemplatepackagesignerDescription,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
