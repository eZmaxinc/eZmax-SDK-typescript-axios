/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { AttemptResponse } from './attempt-response';

/**
 * @type AttemptResponseCompound
 * An Attempt object and children to create a complete structure
 * @export
 */
export type AttemptResponseCompound = AttemptResponse;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A AttemptResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectAttemptResponseCompound
 */
export class DataObjectAttemptResponseCompound {
    dtAttemptStart:string = ''
    sAttemptResult:string = ''
    iAttemptDuration:number = 0
}

/**
 * @export 
 * A AttemptResponseCompound Validation Object
 * @class ValidationObjectAttemptResponseCompound
 */
export class ValidationObjectAttemptResponseCompound {
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


