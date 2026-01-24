# EzsigntemplatepackageRequestCompound

A Ezsigntemplatepackage Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatepackageID** | **number** | The unique ID of the Ezsigntemplatepackage | [optional] [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [default to undefined]
**fkiEzdoctemplatedocumentID** | **number** | The unique ID of the Ezdoctemplatedocument | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sEzsigntemplatepackageDescription** | **string** | The description of the Ezsigntemplatepackage | [default to undefined]
**bEzsigntemplatepackageAdminonly** | **boolean** | Whether the Ezsigntemplatepackage can be accessed by admin users only (eUserType&#x3D;Normal) | [default to undefined]
**bEzsigntemplatepackageIsactive** | **boolean** | Whether the Ezsigntemplatepackage is active or not | [default to undefined]

## Example

```typescript
import { EzsigntemplatepackageRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatepackageRequestCompound = {
    pkiEzsigntemplatepackageID,
    fkiEzsignfoldertypeID,
    fkiEzdoctemplatedocumentID,
    fkiLanguageID,
    sEzsigntemplatepackageDescription,
    bEzsigntemplatepackageAdminonly,
    bEzsigntemplatepackageIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
