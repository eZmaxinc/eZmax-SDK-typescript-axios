# EzsigntemplatepackageResponseCompoundV3

A Ezsigntemplatepackage Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatepackageID** | **number** | The unique ID of the Ezsigntemplatepackage | [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [default to undefined]
**fkiEzdoctemplatedocumentID** | **number** | The unique ID of the Ezdoctemplatedocument | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sEzdoctemplatedocumentNameX** | **string** | The name of the Ezdoctemplatedocument in the language of the requester | [optional] [default to undefined]
**sLanguageNameX** | **string** | The Name of the Language in the language of the requester | [default to undefined]
**sEzsigntemplatepackageDescription** | **string** | The description of the Ezsigntemplatepackage | [default to undefined]
**bEzsigntemplatepackageAdminonly** | **boolean** | Whether the Ezsigntemplatepackage can be accessed by admin users only (eUserType&#x3D;Normal) | [default to undefined]
**bEzsigntemplatepackageNeedvalidation** | **boolean** | Whether the Ezsignbulksend was automatically modified and needs a manual validation | [default to undefined]
**bEzsigntemplatepackageIsactive** | **boolean** | Whether the Ezsigntemplatepackage is active or not | [default to undefined]
**sEzsignfoldertypeNameX** | **string** | The name of the Ezsignfoldertype in the language of the requester | [default to undefined]
**bEzsigntemplatepackageEditallowed** | **boolean** | Whether the Ezsigntemplatepackage if allowed to edit or not | [default to undefined]
**a_objEzsigntemplatepackagesigner** | [**Array&lt;EzsigntemplatepackagesignerResponseCompoundV3&gt;**](EzsigntemplatepackagesignerResponseCompoundV3.md) |  | [default to undefined]
**a_objEzsigntemplatepackagemembership** | [**Array&lt;EzsigntemplatepackagemembershipResponseCompoundV3&gt;**](EzsigntemplatepackagemembershipResponseCompoundV3.md) |  | [default to undefined]

## Example

```typescript
import { EzsigntemplatepackageResponseCompoundV3 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatepackageResponseCompoundV3 = {
    pkiEzsigntemplatepackageID,
    fkiEzsignfoldertypeID,
    fkiEzdoctemplatedocumentID,
    fkiLanguageID,
    sEzdoctemplatedocumentNameX,
    sLanguageNameX,
    sEzsigntemplatepackageDescription,
    bEzsigntemplatepackageAdminonly,
    bEzsigntemplatepackageNeedvalidation,
    bEzsigntemplatepackageIsactive,
    sEzsignfoldertypeNameX,
    bEzsigntemplatepackageEditallowed,
    a_objEzsigntemplatepackagesigner,
    a_objEzsigntemplatepackagemembership,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
