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
 * An Attempt object
 * @export
 * @interface AttemptResponse
 */
export interface AttemptResponse {
    /**
     * Represent a Date Time. The timezone is the one configured in the User\'s profile.
     * @type {string}
     * @memberof AttemptResponse
     */
    /*'dtAttemptStart': string;*/
    'dtAttemptStart': string;
    /**
     * The Success or Failure message of the attempt when we tried to call the URL to deliver the webhook event.
     * @type {string}
     * @memberof AttemptResponse
     */
    /*'sAttemptResult': string;*/
    'sAttemptResult': string;
    /**
     * The number of second it took to process the webhook or get an error
     * @type {number}
     * @memberof AttemptResponse
     */
    /*'iAttemptDuration': number;*/
    'iAttemptDuration': number;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A AttemptResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectAttemptResponse
 */
export class DataObjectAttemptResponse {
   dtAttemptStart:string = ''
   sAttemptResult:string = ''
   iAttemptDuration:number = 0
}

/**
 * @export 
 * A AttemptResponse Validation Object
 * @class ValidationObjectAttemptResponse
 */
export class ValidationObjectAttemptResponse {
   dtAttemptStart = {
      type: 'string',
      required: true
   }
   sAttemptResult = {
      type: 'string',
      required: true
   }
   iAttemptDuration = {
      type: 'integer',
      required: true
   }
} 


