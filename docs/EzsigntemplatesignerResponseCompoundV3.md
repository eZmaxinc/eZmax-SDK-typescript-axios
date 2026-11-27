# EzsigntemplatesignerResponseCompoundV3

A Ezsigntemplatesigner Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatesignerID** | **number** | The unique ID of the Ezsigntemplatesigner | [default to undefined]
**fkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiUsergroupID** | **number** | The unique ID of the Usergroup | [optional] [default to undefined]
**fkiEzdoctemplatedocumentID** | **number** | The unique ID of the Ezdoctemplatedocument | [optional] [default to undefined]
**eEzsigntemplatesignerRole** | [**FieldEEzsigntemplatesignerRole**](FieldEEzsigntemplatesignerRole.md) |  | [optional] [default to undefined]
**eEzsigntemplatesignerMapping** | [**FieldEEzsigntemplatesignerMapping**](FieldEEzsigntemplatesignerMapping.md) |  | [optional] [default to undefined]
**sEzsigntemplatesignerDescription** | **string** | The description of the Ezsigntemplatesigner | [default to undefined]
**sUserName** | **string** | The description of the User in the language of the requester | [optional] [default to undefined]
**sUsergroupNameX** | **string** | The Name of the Usergroup in the language of the requester | [optional] [default to undefined]

## Example

```typescript
import { EzsigntemplatesignerResponseCompoundV3 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatesignerResponseCompoundV3 = {
    pkiEzsigntemplatesignerID,
    fkiEzsigntemplateID,
    fkiUserID,
    fkiUsergroupID,
    fkiEzdoctemplatedocumentID,
    eEzsigntemplatesignerRole,
    eEzsigntemplatesignerMapping,
    sEzsigntemplatesignerDescription,
    sUserName,
    sUsergroupNameX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
