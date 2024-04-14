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



/**
 * A Ezsigntemplate Object
 * @export
 * @interface EzsigntemplateRequest
 */
export interface EzsigntemplateRequest {
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplateRequest
     */
    /*'pkiEzsigntemplateID'?: number;*/
    'pkiEzsigntemplateID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplateRequest
     */
    /*'fkiEzsignfoldertypeID': number;*/
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplateRequest
     */
    /*'fkiLanguageID': number;*/
    'fkiLanguageID': number;
    /**
     * The description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateRequest
     */
    /*'sEzsigntemplateDescription': string;*/
    'sEzsigntemplateDescription': string;
    /**
     * The filename pattern of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateRequest
     */
    /*'sEzsigntemplateFilenamepattern'?: string;*/
    'sEzsigntemplateFilenamepattern'?: string;
    /**
     * Whether the Ezsigntemplate can be accessed by admin users only (eUserType=Normal)
     * @type {boolean}
     * @memberof EzsigntemplateRequest
     */
    /*'bEzsigntemplateAdminonly': boolean;*/
    'bEzsigntemplateAdminonly': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateRequest
 */
export class DataObjectEzsigntemplateRequest {
   pkiEzsigntemplateID?:number = undefined
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sEzsigntemplateDescription:string = ''
   sEzsigntemplateFilenamepattern?:string = undefined
   bEzsigntemplateAdminonly:boolean = false
}

/**
 * @export 
 * A EzsigntemplateRequest Validation Object
 * @class ValidationObjectEzsigntemplateRequest
 */
export class ValidationObjectEzsigntemplateRequest {
   pkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfoldertypeID = {
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
} 


