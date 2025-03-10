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



/**
 * A Ezsignbulksend Object
 * @export
 * @interface EzsignbulksendRequest
 */
export interface EzsignbulksendRequest {
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendRequest
     */
    /*'pkiEzsignbulksendID'?: number;*/
    'pkiEzsignbulksendID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsignbulksendRequest
     */
    /*'fkiEzsignfoldertypeID': number;*/
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsignbulksendRequest
     */
    /*'fkiLanguageID': number;*/
    'fkiLanguageID': number;
    /**
     * The description of the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendRequest
     */
    /*'sEzsignbulksendDescription': string;*/
    'sEzsignbulksendDescription': string;
    /**
     * Note about the Ezsignbulksend
     * @type {string}
     * @memberof EzsignbulksendRequest
     */
    /*'tEzsignbulksendNote': string;*/
    'tEzsignbulksendNote': string;
    /**
     * Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsignbulksendRequest
     */
    /*'bEzsignbulksendNeedvalidation': boolean;*/
    'bEzsignbulksendNeedvalidation': boolean;
    /**
     * Whether the Ezsignbulksend is active or not
     * @type {boolean}
     * @memberof EzsignbulksendRequest
     */
    /*'bEzsignbulksendIsactive': boolean;*/
    'bEzsignbulksendIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksendRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendRequest
 */
export class DataObjectEzsignbulksendRequest {
   pkiEzsignbulksendID?:number = undefined
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sEzsignbulksendDescription:string = ''
   tEzsignbulksendNote:string = ''
   bEzsignbulksendNeedvalidation:boolean = false
   bEzsignbulksendIsactive:boolean = false
}

/**
 * @export 
 * A EzsignbulksendRequest Validation Object
 * @class ValidationObjectEzsignbulksendRequest
 */
export class ValidationObjectEzsignbulksendRequest {
   pkiEzsignbulksendID = {
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
   sEzsignbulksendDescription = {
      type: 'string',
      required: true
   }
   tEzsignbulksendNote = {
      type: 'string',
      required: true
   }
   bEzsignbulksendNeedvalidation = {
      type: 'boolean',
      required: true
   }
   bEzsignbulksendIsactive = {
      type: 'boolean',
      required: true
   }
} 


