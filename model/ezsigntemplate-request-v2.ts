/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplateType } from './field-eezsigntemplate-type';

/**
 * A Ezsigntemplate Object
 * @export
 * @interface EzsigntemplateRequestV2
 */
export interface EzsigntemplateRequestV2 {
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplateRequestV2
     */
    /*'pkiEzsigntemplateID'?: number;*/
    'pkiEzsigntemplateID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplateRequestV2
     */
    /*'fkiEzsignfoldertypeID'?: number;*/
    'fkiEzsignfoldertypeID'?: number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplateRequestV2
     */
    /*'fkiLanguageID': number;*/
    'fkiLanguageID': number;
    /**
     * The description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateRequestV2
     */
    /*'sEzsigntemplateDescription': string;*/
    'sEzsigntemplateDescription': string;
    /**
     * The filename pattern of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateRequestV2
     */
    /*'sEzsigntemplateFilenamepattern'?: string;*/
    'sEzsigntemplateFilenamepattern'?: string;
    /**
     * Whether the Ezsigntemplate can be accessed by admin users only (eUserType=Normal)
     * @type {boolean}
     * @memberof EzsigntemplateRequestV2
     */
    /*'bEzsigntemplateAdminonly': boolean;*/
    'bEzsigntemplateAdminonly': boolean;
    /**
     * 
     * @type {FieldEEzsigntemplateType}
     * @memberof EzsigntemplateRequestV2
     */
    /*'eEzsigntemplateType': FieldEEzsigntemplateType;*/
    'eEzsigntemplateType': FieldEEzsigntemplateType;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateRequestV2 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateRequestV2
 */
export class DataObjectEzsigntemplateRequestV2 {
   pkiEzsigntemplateID?:number = undefined
   fkiEzsignfoldertypeID?:number = undefined
   fkiLanguageID:number = 0
   sEzsigntemplateDescription:string = ''
   sEzsigntemplateFilenamepattern?:string = undefined
   bEzsigntemplateAdminonly:boolean = false
   eEzsigntemplateType:FieldEEzsigntemplateType = 'User'
}

/**
 * @export 
 * A EzsigntemplateRequestV2 Validation Object
 * @class ValidationObjectEzsigntemplateRequestV2
 */
export class ValidationObjectEzsigntemplateRequestV2 {
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
   sEzsigntemplateDescription = {
      type: 'string',
      required: true
   }
   sEzsigntemplateFilenamepattern = {
      type: 'string',
      pattern: '/^.{1,50}$/',
      required: false
   }
   bEzsigntemplateAdminonly = {
      type: 'boolean',
      required: true
   }
   eEzsigntemplateType = {
      type: 'enum',
      allowableValues: ['User','Usergroup','Company'],
      required: true
   }
} 

