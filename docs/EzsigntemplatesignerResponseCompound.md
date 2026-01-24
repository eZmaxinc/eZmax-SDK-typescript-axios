# EzsigntemplatesignerResponseCompound

A Ezsigntemplatesigner Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatesignerID** | **number** | The unique ID of the Ezsigntemplatesigner | [default to undefined]
**fkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiUsergroupID** | **number** | The unique ID of the Usergroup | [optional] [default to undefined]
**fkiEzdoctemplatedocumentID** | **number** | The unique ID of the Ezdoctemplatedocument | [optional] [default to undefined]
**bEzsigntemplatesignerReceivecopy** | **boolean** | If this flag is true. The signatory will receive a copy of every signed Ezsigndocument even if it ain\&#39;t required to sign the document. | [optional] [default to undefined]
**eEzsigntemplatesignerMapping** | [**FieldEEzsigntemplatesignerMapping**](FieldEEzsigntemplatesignerMapping.md) |  | [optional] [default to undefined]
**sEzsigntemplatesignerDescription** | **string** | The description of the Ezsigntemplatesigner | [default to undefined]
**sUserName** | **string** | The description of the User in the language of the requester | [optional] [default to undefined]
**sUsergroupNameX** | **string** | The Name of the Usergroup in the language of the requester | [optional] [default to undefined]

## Example

```typescript
import { EzsigntemplatesignerResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatesignerResponseCompound = {
    pkiEzsigntemplatesignerID,
    fkiEzsigntemplateID,
    fkiUserID,
    fkiUsergroupID,
    fkiEzdoctemplatedocumentID,
    bEzsigntemplatesignerReceivecopy,
    eEzsigntemplatesignerMapping,
    sEzsigntemplatesignerDescription,
    sUserName,
    sUsergroupNameX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
