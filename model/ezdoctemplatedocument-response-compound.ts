/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EzdoctemplatedocumentResponse } from './ezdoctemplatedocument-response';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzdoctemplatedocumentPrivacylevel } from './field-eezdoctemplatedocument-privacylevel';
// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualEzdoctemplatedocumentName } from './multilingual-ezdoctemplatedocument-name';

/**
 * @type EzdoctemplatedocumentResponseCompound
 * A Ezdoctemplatedocument Object
 * @export
 */
/*export type EzdoctemplatedocumentResponseCompound = EzdoctemplatedocumentResponse;*/
export interface EzdoctemplatedocumentResponseCompound {
    /**
     * The unique ID of the Ezdoctemplatedocument
     * @type {number}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    pkiEzdoctemplatedocumentID:number 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    fkiLanguageID:number 
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    fkiEzsignfoldertypeID?:number 
    /**
     * The unique ID of the Ezdoctemplatetype
     * @type {number}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    fkiEzdoctemplatetypeID:number 
    /**
     * The unique ID of the Ezdoctemplatefieldtypecategory
     * @type {number}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    fkiEzdoctemplatefieldtypecategoryID:number 
    /**
     * 
     * @type {FieldEEzdoctemplatedocumentPrivacylevel}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    eEzdoctemplatedocumentPrivacylevel?:FieldEEzdoctemplatedocumentPrivacylevel 
    /**
     * Whether the ezdoctemplatedocument is active or not
     * @type {boolean}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    bEzdoctemplatedocumentIsactive:boolean 
    /**
     * 
     * @type {MultilingualEzdoctemplatedocumentName}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    objEzdoctemplatedocumentName:MultilingualEzdoctemplatedocumentName 
    /**
     * The name of the Ezdoctemplatedocument in the language of the requester
     * @type {string}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    sEzdoctemplatedocumentNameX?:string 
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    sEzsignfoldertypeNameX?:string 
    /**
     * The description of the Ezdoctemplatefieldtypecategory in the language of the requester
     * @type {string}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    sEzdoctemplatefieldtypecategoryDescriptionX:string 
    /**
     * The description of the Ezdoctemplatetype in the language of the requester
     * @type {string}
     * @memberof EzdoctemplatedocumentResponseCompound
     */
    sEzdoctemplatetypeDescriptionX:string 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualEzdoctemplatedocumentName } from './'
// @ts-ignore
import { ValidationObjectMultilingualEzdoctemplatedocumentName } from './'

/**
 * @export 
 * A EzdoctemplatedocumentResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzdoctemplatedocumentResponseCompound
 */
export class DataObjectEzdoctemplatedocumentResponseCompound {
    pkiEzdoctemplatedocumentID:number = 0
    fkiLanguageID:number = 0
    fkiEzsignfoldertypeID?:number = undefined
    fkiEzdoctemplatetypeID:number = 0
    fkiEzdoctemplatefieldtypecategoryID:number = 0
    eEzdoctemplatedocumentPrivacylevel?:FieldEEzdoctemplatedocumentPrivacylevel = undefined
    bEzdoctemplatedocumentIsactive:boolean = false
    objEzdoctemplatedocumentName:MultilingualEzdoctemplatedocumentName = new DataObjectMultilingualEzdoctemplatedocumentName()
    sEzdoctemplatedocumentNameX?:string = undefined
    sEzsignfoldertypeNameX?:string = undefined
    sEzdoctemplatefieldtypecategoryDescriptionX:string = ''
    sEzdoctemplatetypeDescriptionX:string = ''
}

/**
 * @export 
 * A EzdoctemplatedocumentResponseCompound Validation Object
 * @class ValidationObjectEzdoctemplatedocumentResponseCompound
 */
export class ValidationObjectEzdoctemplatedocumentResponseCompound {
   pkiEzdoctemplatedocumentID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiEzdoctemplatetypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   fkiEzdoctemplatefieldtypecategoryID = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   eEzdoctemplatedocumentPrivacylevel = {
      type: 'enum',
      allowableValues: ['Company','Ezsignfoldertype','User'],
      required: false
   }
   bEzdoctemplatedocumentIsactive = {
      type: 'boolean',
      required: true
   }
   objEzdoctemplatedocumentName = new ValidationObjectMultilingualEzdoctemplatedocumentName()
   sEzdoctemplatedocumentNameX = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: false
   }
   sEzdoctemplatefieldtypecategoryDescriptionX = {
      type: 'string',
      pattern: /^.{0,55}$/,
      required: true
   }
   sEzdoctemplatetypeDescriptionX = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: true
   }
} 


