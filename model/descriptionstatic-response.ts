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
 * A Descriptionstatic Object
 * @export
 * @interface DescriptionstaticResponse
 */
export interface DescriptionstaticResponse {
    /**
     * The unique ID of the Descriptionstatic
     * @type {number}
     * @memberof DescriptionstaticResponse
     */
    'pkiDescriptionstaticID': number;
    /**
     * The description of the Descriptionstatic
     * @type {string}
     * @memberof DescriptionstaticResponse
     */
    'sDescriptionstaticDescription': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DescriptionstaticResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDescriptionstaticResponse
 */
export class DataObjectDescriptionstaticResponse {
   pkiDescriptionstaticID:number = 0
   sDescriptionstaticDescription:string = ''
}

/**
 * @export 
 * A DescriptionstaticResponse Validation Object
 * @class ValidationObjectDescriptionstaticResponse
 */
export class ValidationObjectDescriptionstaticResponse {
   pkiDescriptionstaticID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sDescriptionstaticDescription = {
      type: 'string',
      required: true
   }
} 


