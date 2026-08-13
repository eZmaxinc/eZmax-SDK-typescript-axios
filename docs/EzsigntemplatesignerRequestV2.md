# EzsigntemplatesignerRequestV2

A Ezsigntemplatesigner Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatesignerID** | **number** | The unique ID of the Ezsigntemplatesigner | [optional] [default to undefined]
**fkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiUsergroupID** | **number** | The unique ID of the Usergroup | [optional] [default to undefined]
**fkiEzdoctemplatedocumentID** | **number** | The unique ID of the Ezdoctemplatedocument | [optional] [default to undefined]
**eEzsigntemplatesignerRole** | [**FieldEEzsigntemplatesignerRole**](FieldEEzsigntemplatesignerRole.md) |  | [optional] [default to undefined]
**eEzsigntemplatesignerMapping** | [**FieldEEzsigntemplatesignerMapping**](FieldEEzsigntemplatesignerMapping.md) |  | [optional] [default to undefined]
**sEzsigntemplatesignerDescription** | **string** | The description of the Ezsigntemplatesigner | [default to undefined]

## Example

```typescript
import { EzsigntemplatesignerRequestV2 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatesignerRequestV2 = {
    pkiEzsigntemplatesignerID,
    fkiEzsigntemplateID,
    fkiUserID,
    fkiUsergroupID,
    fkiEzdoctemplatedocumentID,
    eEzsigntemplatesignerRole,
    eEzsigntemplatesignerMapping,
    sEzsigntemplatesignerDescription,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
