/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Ezsigntemplatepackage Object
 * @export
 * @interface EzsigntemplatepackageRequest
 */
export interface EzsigntemplatepackageRequest {
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackageRequest
     */
    'pkiEzsigntemplatepackageID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplatepackageRequest
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplatepackageRequest
     */
    'fkiLanguageID': number;
    /**
     * The description of the Ezsigntemplatepackage
     * @type {string}
     * @memberof EzsigntemplatepackageRequest
     */
    'sEzsigntemplatepackageDescription': string;
    /**
     * Whether the Ezsigntemplatepackage can be accessed by admin users only (eUserType=Normal)
     * @type {boolean}
     * @memberof EzsigntemplatepackageRequest
     */
    'bEzsigntemplatepackageAdminonly': boolean;
    /**
     * Whether the Ezsigntemplatepackage is active or not
     * @type {boolean}
     * @memberof EzsigntemplatepackageRequest
     */
    'bEzsigntemplatepackageIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackageRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageRequest
 */
export class DataObjectEzsigntemplatepackageRequest {
   pkiEzsigntemplatepackageID?:number = undefined
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sEzsigntemplatepackageDescription:string = ''
   bEzsigntemplatepackageAdminonly:boolean = false
   bEzsigntemplatepackageIsactive:boolean = false
}

/**
 * @export 
 * A EzsigntemplatepackageRequest Validation Object
 * @class ValidationObjectEzsigntemplatepackageRequest
 */
export class ValidationObjectEzsigntemplatepackageRequest {
   pkiEzsigntemplatepackageID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sEzsigntemplatepackageDescription = {
      type: 'string',
      required: true
   }
   bEzsigntemplatepackageAdminonly = {
      type: 'boolean',
      required: true
   }
   bEzsigntemplatepackageIsactive = {
      type: 'boolean',
      required: true
   }
} 


