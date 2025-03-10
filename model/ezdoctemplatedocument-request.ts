/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzdoctemplatedocumentPrivacylevel } from './field-eezdoctemplatedocument-privacylevel';
// May contain unused imports in some cases
// @ts-ignore
import type { MultilingualEzdoctemplatedocumentName } from './multilingual-ezdoctemplatedocument-name';

/**
 * A Ezdoctemplatedocument Object
 * @export
 * @interface EzdoctemplatedocumentRequest
 */
export interface EzdoctemplatedocumentRequest {
    /**
     * The unique ID of the Ezdoctemplatedocument
     * @type {number}
     * @memberof EzdoctemplatedocumentRequest
     */
    /*'pkiEzdoctemplatedocumentID'?: number;*/
    'pkiEzdoctemplatedocumentID'?: number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzdoctemplatedocumentRequest
     */
    /*'fkiLanguageID': number;*/
    'fkiLanguageID': number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzdoctemplatedocumentRequest
     */
    /*'fkiEzsignfoldertypeID'?: number;*/
    'fkiEzsignfoldertypeID'?: number;
    /**
     * The unique ID of the Ezdoctemplatetype
     * @type {number}
     * @memberof EzdoctemplatedocumentRequest
     */
    /*'fkiEzdoctemplatetypeID': number;*/
    'fkiEzdoctemplatetypeID': number;
    /**
     * The unique ID of the Ezdoctemplatefieldtypecategory
     * @type {number}
     * @memberof EzdoctemplatedocumentRequest
     */
    /*'fkiEzdoctemplatefieldtypecategoryID': number;*/
    'fkiEzdoctemplatefieldtypecategoryID': number;
    /**
     * 
     * @type {FieldEEzdoctemplatedocumentPrivacylevel}
     * @memberof EzdoctemplatedocumentRequest
     */
    /*'eEzdoctemplatedocumentPrivacylevel'?: FieldEEzdoctemplatedocumentPrivacylevel;*/
    'eEzdoctemplatedocumentPrivacylevel'?: FieldEEzdoctemplatedocumentPrivacylevel;
    /**
     * Whether the ezdoctemplatedocument is active or not
     * @type {boolean}
     * @memberof EzdoctemplatedocumentRequest
     */
    /*'bEzdoctemplatedocumentIsactive': boolean;*/
    'bEzdoctemplatedocumentIsactive': boolean;
    /**
     * 
     * @type {MultilingualEzdoctemplatedocumentName}
     * @memberof EzdoctemplatedocumentRequest
     */
    /*'objEzdoctemplatedocumentName': MultilingualEzdoctemplatedocumentName;*/
    'objEzdoctemplatedocumentName': MultilingualEzdoctemplatedocumentName;
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
 * A EzdoctemplatedocumentRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzdoctemplatedocumentRequest
 */
export class DataObjectEzdoctemplatedocumentRequest {
   pkiEzdoctemplatedocumentID?:number = undefined
   fkiLanguageID:number = 0
   fkiEzsignfoldertypeID?:number = undefined
   fkiEzdoctemplatetypeID:number = 0
   fkiEzdoctemplatefieldtypecategoryID:number = 0
   eEzdoctemplatedocumentPrivacylevel?:FieldEEzdoctemplatedocumentPrivacylevel = undefined
   bEzdoctemplatedocumentIsactive:boolean = false
   objEzdoctemplatedocumentName:MultilingualEzdoctemplatedocumentName = new DataObjectMultilingualEzdoctemplatedocumentName()
}

/**
 * @export 
 * A EzdoctemplatedocumentRequest Validation Object
 * @class ValidationObjectEzdoctemplatedocumentRequest
 */
export class ValidationObjectEzdoctemplatedocumentRequest {
   pkiEzdoctemplatedocumentID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
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
} 


