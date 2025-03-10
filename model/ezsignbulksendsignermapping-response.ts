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
 * A Ezsignbulksendsignermapping Object
 * @export
 * @interface EzsignbulksendsignermappingResponse
 */
export interface EzsignbulksendsignermappingResponse {
    /**
     * The unique ID of the Ezsignbulksendsignermapping
     * @type {number}
     * @memberof EzsignbulksendsignermappingResponse
     */
    /*'pkiEzsignbulksendsignermappingID': number;*/
    'pkiEzsignbulksendsignermappingID': number;
    /**
     * The unique ID of the Ezsignbulksend
     * @type {number}
     * @memberof EzsignbulksendsignermappingResponse
     */
    /*'fkiEzsignbulksendID': number;*/
    'fkiEzsignbulksendID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsignbulksendsignermappingResponse
     */
    /*'fkiUserID'?: number;*/
    'fkiUserID'?: number;
    /**
     * The description of the Ezsignbulksendsignermapping
     * @type {string}
     * @memberof EzsignbulksendsignermappingResponse
     */
    /*'sEzsignbulksendsignermappingDescription': string;*/
    'sEzsignbulksendsignermappingDescription': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignbulksendsignermappingResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendsignermappingResponse
 */
export class DataObjectEzsignbulksendsignermappingResponse {
   pkiEzsignbulksendsignermappingID:number = 0
   fkiEzsignbulksendID:number = 0
   fkiUserID?:number = undefined
   sEzsignbulksendsignermappingDescription:string = ''
}

/**
 * @export 
 * A EzsignbulksendsignermappingResponse Validation Object
 * @class ValidationObjectEzsignbulksendsignermappingResponse
 */
export class ValidationObjectEzsignbulksendsignermappingResponse {
   pkiEzsignbulksendsignermappingID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignbulksendID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   sEzsignbulksendsignermappingDescription = {
      type: 'string',
      required: true
   }
} 


