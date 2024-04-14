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



/**
 * A Ezsigntemplatesigner Object
 * @export
 * @interface EzsigntemplatesignerRequest
 */
export interface EzsigntemplatesignerRequest {
    /**
     * The unique ID of the Ezsigntemplatesigner
     * @type {number}
     * @memberof EzsigntemplatesignerRequest
     */
    /*'pkiEzsigntemplatesignerID'?: number;*/
    'pkiEzsigntemplatesignerID'?: number;
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplatesignerRequest
     */
    /*'fkiEzsigntemplateID': number;*/
    'fkiEzsigntemplateID': number;
    /**
     * The description of the Ezsigntemplatesigner
     * @type {string}
     * @memberof EzsigntemplatesignerRequest
     */
    /*'sEzsigntemplatesignerDescription': string;*/
    'sEzsigntemplatesignerDescription': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatesignerRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignerRequest
 */
export class DataObjectEzsigntemplatesignerRequest {
   pkiEzsigntemplatesignerID?:number = undefined
   fkiEzsigntemplateID:number = 0
   sEzsigntemplatesignerDescription:string = ''
}

/**
 * @export 
 * A EzsigntemplatesignerRequest Validation Object
 * @class ValidationObjectEzsigntemplatesignerRequest
 */
export class ValidationObjectEzsigntemplatesignerRequest {
   pkiEzsigntemplatesignerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzsigntemplateID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsigntemplatesignerDescription = {
      type: 'string',
      pattern: '/^.{1,50}$/',
      required: true
   }
} 


