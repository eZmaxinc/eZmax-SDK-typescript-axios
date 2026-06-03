# EzdoctemplatedocumentResponseCompound

A Ezdoctemplatedocument Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzdoctemplatedocumentID** | **number** | The unique ID of the Ezdoctemplatedocument | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [optional] [default to undefined]
**fkiEzdoctemplatetypeID** | **number** | The unique ID of the Ezdoctemplatetype | [default to undefined]
**fkiEzdoctemplatefieldtypecategoryID** | **number** | The unique ID of the Ezdoctemplatefieldtypecategory | [optional] [default to undefined]
**eEzdoctemplatedocumentPrivacylevel** | [**FieldEEzdoctemplatedocumentPrivacylevel**](FieldEEzdoctemplatedocumentPrivacylevel.md) |  | [optional] [default to undefined]
**bEzdoctemplatedocumentIsactive** | **boolean** | Whether the ezdoctemplatedocument is active or not | [default to undefined]
**objEzdoctemplatedocumentName** | [**MultilingualEzdoctemplatedocumentName**](MultilingualEzdoctemplatedocumentName.md) |  | [default to undefined]
**sEzdoctemplatedocumentNameX** | **string** | The name of the Ezdoctemplatedocument in the language of the requester | [optional] [default to undefined]
**sEzsignfoldertypeNameX** | **string** | The name of the Ezsignfoldertype in the language of the requester | [optional] [default to undefined]
**sEzdoctemplatefieldtypecategoryDescriptionX** | **string** | The description of the Ezdoctemplatefieldtypecategory in the language of the requester | [optional] [default to undefined]
**sEzdoctemplatetypeDescriptionX** | **string** | The description of the Ezdoctemplatetype in the language of the requester | [default to undefined]

## Example

```typescript
import { EzdoctemplatedocumentResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzdoctemplatedocumentResponseCompound = {
    pkiEzdoctemplatedocumentID,
    fkiLanguageID,
    fkiEzsignfoldertypeID,
    fkiEzdoctemplatetypeID,
    fkiEzdoctemplatefieldtypecategoryID,
    eEzdoctemplatedocumentPrivacylevel,
    bEzdoctemplatedocumentIsactive,
    objEzdoctemplatedocumentName,
    sEzdoctemplatedocumentNameX,
    sEzsignfoldertypeNameX,
    sEzdoctemplatefieldtypecategoryDescriptionX,
    sEzdoctemplatetypeDescriptionX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
