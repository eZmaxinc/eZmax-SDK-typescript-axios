# EzsigntemplatepackagesignerResponseV3

A Ezsigntemplatepackagesigner Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatepackagesignerID** | **number** | The unique ID of the Ezsigntemplatepackagesigner | [default to undefined]
**fkiEzsigntemplatepackageID** | **number** | The unique ID of the Ezsigntemplatepackage | [default to undefined]
**fkiEzdoctemplatedocumentID** | **number** | The unique ID of the Ezdoctemplatedocument | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiUsergroupID** | **number** | The unique ID of the Usergroup | [optional] [default to undefined]
**sEzdoctemplatedocumentNameX** | **string** | The name of the Ezdoctemplatedocument in the language of the requester | [optional] [default to undefined]
**eEzsigntemplatepackagesignerRole** | [**FieldEEzsigntemplatepackagesignerRole**](FieldEEzsigntemplatepackagesignerRole.md) |  | [optional] [default to undefined]
**eEzsigntemplatepackagesignerMapping** | [**FieldEEzsigntemplatepackagesignerMapping**](FieldEEzsigntemplatepackagesignerMapping.md) |  | [optional] [default to undefined]
**sEzsigntemplatepackagesignerDescription** | **string** | The description of the Ezsigntemplatepackagesigner | [default to undefined]
**sUserName** | **string** | The description of the User in the language of the requester | [optional] [default to undefined]
**sUsergroupNameX** | **string** | The Name of the Usergroup in the language of the requester | [optional] [default to undefined]

## Example

```typescript
import { EzsigntemplatepackagesignerResponseV3 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatepackagesignerResponseV3 = {
    pkiEzsigntemplatepackagesignerID,
    fkiEzsigntemplatepackageID,
    fkiEzdoctemplatedocumentID,
    fkiUserID,
    fkiUsergroupID,
    sEzdoctemplatedocumentNameX,
    eEzsigntemplatepackagesignerRole,
    eEzsigntemplatepackagesignerMapping,
    sEzsigntemplatepackagesignerDescription,
    sUserName,
    sUsergroupNameX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
