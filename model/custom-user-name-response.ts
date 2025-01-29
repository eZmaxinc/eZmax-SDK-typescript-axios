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
 * A User name Object
 * @export
 * @interface CustomUserNameResponse
 */
export interface CustomUserNameResponse {
    /**
     * The last name of the user
     * @type {string}
     * @memberof CustomUserNameResponse
     */
    /*'sUserLastname': string;*/
    'sUserLastname': string;
    /**
     * The first name of the user
     * @type {string}
     * @memberof CustomUserNameResponse
     */
    /*'sUserFirstname': string;*/
    'sUserFirstname': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomUserNameResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomUserNameResponse
 */
export class DataObjectCustomUserNameResponse {
   sUserLastname:string = ''
   sUserFirstname:string = ''
}

/**
 * @export 
 * A CustomUserNameResponse Validation Object
 * @class ValidationObjectCustomUserNameResponse
 */
export class ValidationObjectCustomUserNameResponse {
   sUserLastname = {
      type: 'string',
      required: true
   }
   sUserFirstname = {
      type: 'string',
      required: true
   }
} 


