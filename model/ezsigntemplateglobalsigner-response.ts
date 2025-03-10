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
 * A Ezsigntemplateglobalsigner Object
 * @export
 * @interface EzsigntemplateglobalsignerResponse
 */
export interface EzsigntemplateglobalsignerResponse {
    /**
     * The unique ID of the Ezsigntemplateglobalsigner
     * @type {number}
     * @memberof EzsigntemplateglobalsignerResponse
     */
    /*'pkiEzsigntemplateglobalsignerID': number;*/
    'pkiEzsigntemplateglobalsignerID': number;
    /**
     * The unique ID of the Ezsigntemplateglobal
     * @type {number}
     * @memberof EzsigntemplateglobalsignerResponse
     */
    /*'fkiEzsigntemplateglobalID': number;*/
    'fkiEzsigntemplateglobalID': number;
    /**
     * The description of the Ezsigntemplateglobalsigner
     * @type {string}
     * @memberof EzsigntemplateglobalsignerResponse
     */
    /*'sEzsigntemplateglobalsignerDescription': string;*/
    'sEzsigntemplateglobalsignerDescription': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplateglobalsignerResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplateglobalsignerResponse
 */
export class DataObjectEzsigntemplateglobalsignerResponse {
   pkiEzsigntemplateglobalsignerID:number = 0
   fkiEzsigntemplateglobalID:number = 0
   sEzsigntemplateglobalsignerDescription:string = ''
}

/**
 * @export 
 * A EzsigntemplateglobalsignerResponse Validation Object
 * @class ValidationObjectEzsigntemplateglobalsignerResponse
 */
export class ValidationObjectEzsigntemplateglobalsignerResponse {
   pkiEzsigntemplateglobalsignerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsigntemplateglobalID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEzsigntemplateglobalsignerDescription = {
      type: 'string',
      pattern: /^.{1,50}$/,
      required: true
   }
} 


