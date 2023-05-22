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


// May contain unused imports in some cases
// @ts-ignore
import { EmailstaticResponse } from './emailstatic-response';

/**
 * @type EmailstaticResponseCompound
 * An Emailstatic Object and children to create a complete structure
 * @export
 */
export type EmailstaticResponseCompound = EmailstaticResponse;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EmailstaticResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEmailstaticResponseCompound
 */
export class DataObjectEmailstaticResponseCompound {
   pkiEmailstaticID:number = 0
   sEmailstaticAddress:string = ''
}

/**
 * @export 
 * A EmailstaticResponseCompound Validation Object
 * @class ValidationObjectEmailstaticResponseCompound
 */
export class ValidationObjectEmailstaticResponseCompound {
   pkiEmailstaticID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sEmailstaticAddress = {
      type: 'string',
      required: true
   }
} 


