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
import type { EzsigntemplateRequestV3 } from './ezsigntemplate-request-v3';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplateRecognition } from './field-eezsigntemplate-recognition';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEEzsigntemplateType } from './field-eezsigntemplate-type';

/**
 * @type EzsigntemplateRequestCompoundV3
 * A Ezsigntemplate Object and children
 * @export
 */
/*export type EzsigntemplateRequestCompoundV3 = EzsigntemplateRequestV3;*/
export interface EzsigntemplateRequestCompoundV3 {
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplateRequestCompoundV3
     */
    pkiEzsigntemplateID?:number 
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplateRequestCompoundV3
     */
    fkiEzsignfoldertypeID?:number 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplateRequestCompoundV3
     */
    fkiLanguageID:number 
    /**
     * The unique ID of the Ezdoctemplatedocument
     * @type {number}
     * @memberof EzsigntemplateRequestCompoundV3
     */
    fkiEzdoctemplatedocumentID?:number 
    /**
     * The description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateRequestCompoundV3
     */
    sEzsigntemplateDescription:string 
    /**
     * The external description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateRequestCompoundV3
     */
    sEzsigntemplateExternaldescription?:string 
    /**
     * The comment of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateRequestCompoundV3
     */
    tEzsigntemplateComment?:string 
    /**
     * 
     * @type {FieldEEzsigntemplateRecognition}
     * @memberof EzsigntemplateRequestCompoundV3
     */
    eEzsigntemplateRecognition?:FieldEEzsigntemplateRecognition 
    /**
     * The filename regexp of the Ezsigntemplate.
     * @type {string}
     * @memberof EzsigntemplateRequestCompoundV3
     */
    sEzsigntemplateFilenameregexp?:string 
    /**
     * Whether the Ezsigntemplate can be accessed by admin users only (eUserType=Normal)
     * @type {boolean}
     * @memberof EzsigntemplateRequestCompoundV3
     */
    bEzsigntemplateAdminonly:boolean 
    /**
     * 
     * @type {FieldEEzsigntemplateType}
     * @memberof EzsigntemplateRequestCompoundV3
     */
    eEzsigntemplateType:FieldEEzsigntemplateType 
}



/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateRequestCompoundV3 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateRequestCompoundV3
 */
export class DataObjectEzsigntemplateRequestCompoundV3 {
    pkiEzsigntemplateID?:number = undefined
    fkiEzsignfoldertypeID?:number = undefined
    fkiLanguageID:number = 0
    fkiEzdoctemplatedocumentID?:number = undefined
    sEzsigntemplateDescription:string = ''
    sEzsigntemplateExternaldescription?:string = undefined
    tEzsigntemplateComment?:string = undefined
    eEzsigntemplateRecognition?:FieldEEzsigntemplateRecognition = undefined
    sEzsigntemplateFilenameregexp?:string = undefined
    bEzsigntemplateAdminonly:boolean = false
    eEzsigntemplateType:FieldEEzsigntemplateType = 'User'
}

/**
 * @export 
 * A EzsigntemplateRequestCompoundV3 Validation Object
 * @class ValidationObjectEzsigntemplateRequestCompoundV3
 */
export class ValidationObjectEzsigntemplateRequestCompoundV3 {
   pkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfoldertypeID = {
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
   fkiEzdoctemplatedocumentID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   sEzsigntemplateDescription = {
      type: 'string',
      pattern: /^.{0,80}$/,
      required: true
   }
   sEzsigntemplateExternaldescription = {
      type: 'string',
      pattern: /^.{0,75}$/,
      required: false
   }
   tEzsigntemplateComment = {
      type: 'string',
      required: false
   }
   eEzsigntemplateRecognition = {
      type: 'enum',
      allowableValues: ['No','Filename','Content'],
      required: false
   }
   sEzsigntemplateFilenameregexp = {
      type: 'string',
      pattern: /^.{1,50}$/,
      required: false
   }
   bEzsigntemplateAdminonly = {
      type: 'boolean',
      required: true
   }
   eEzsigntemplateType = {
      type: 'enum',
      allowableValues: ['User','Usergroup','Company','Ezsignfoldertype'],
      required: true
   }
} 


