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
 * Generic DropdownElement Response
 * @export
 * @interface CustomDropdownElementResponse
 */
export interface CustomDropdownElementResponse {
    /**
     * The Description of the element
     * @type {string}
     * @memberof CustomDropdownElementResponse
     */
    /*'sLabel': string;*/
    'sLabel': string;
    /**
     * The Value of the element
     * @type {string}
     * @memberof CustomDropdownElementResponse
     */
    /*'sValue': string;*/
    'sValue': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomDropdownElementResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomDropdownElementResponse
 */
export class DataObjectCustomDropdownElementResponse {
   sLabel:string = ''
   sValue:string = ''
}

/**
 * @export 
 * A CustomDropdownElementResponse Validation Object
 * @class ValidationObjectCustomDropdownElementResponse
 */
export class ValidationObjectCustomDropdownElementResponse {
   sLabel = {
      type: 'string',
      required: true
   }
   sValue = {
      type: 'string',
      required: true
   }
} 


