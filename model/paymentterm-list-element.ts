/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FieldEPaymenttermType } from './field-epaymentterm-type';

/**
 * A Paymentterm List Element
 * @export
 * @interface PaymenttermListElement
 */
export interface PaymenttermListElement {
    /**
     * The unique ID of the Paymentterm
     * @type {number}
     * @memberof PaymenttermListElement
     */
    /*'pkiPaymenttermID': number;*/
    'pkiPaymenttermID': number;
    /**
     * The code of the Paymentterm
     * @type {string}
     * @memberof PaymenttermListElement
     */
    /*'sPaymenttermCode': string;*/
    'sPaymenttermCode': string;
    /**
     * 
     * @type {FieldEPaymenttermType}
     * @memberof PaymenttermListElement
     */
    /*'ePaymenttermType': FieldEPaymenttermType;*/
    'ePaymenttermType': FieldEPaymenttermType;
    /**
     * The day of the Paymentterm
     * @type {number}
     * @memberof PaymenttermListElement
     */
    /*'iPaymenttermDay': number;*/
    'iPaymenttermDay': number;
    /**
     * The description of the Paymentterm in the language of the requester
     * @type {string}
     * @memberof PaymenttermListElement
     */
    /*'sPaymenttermDescriptionX': string;*/
    'sPaymenttermDescriptionX': string;
    /**
     * Whether the Paymentterm is active or not
     * @type {boolean}
     * @memberof PaymenttermListElement
     */
    /*'bPaymenttermIsactive': boolean;*/
    'bPaymenttermIsactive': boolean;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A PaymenttermListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermListElement
 */
export class DataObjectPaymenttermListElement {
   pkiPaymenttermID:number = 0
   sPaymenttermCode:string = ''
   ePaymenttermType:FieldEPaymenttermType = 'Days'
   iPaymenttermDay:number = 0
   sPaymenttermDescriptionX:string = ''
   bPaymenttermIsactive:boolean = false
}

/**
 * @export 
 * A PaymenttermListElement Validation Object
 * @class ValidationObjectPaymenttermListElement
 */
export class ValidationObjectPaymenttermListElement {
   pkiPaymenttermID = {
      type: 'integer',
      required: true
   }
   sPaymenttermCode = {
      type: 'string',
      pattern: '/^[A-Z0-9]{1,4}$/',
      required: true
   }
   ePaymenttermType = {
      type: 'enum',
      allowableValues: ['Days','Dayofthemonth'],
      required: true
   }
   iPaymenttermDay = {
      type: 'integer',
      minimum: 0,
      maximum: 255,
      required: true
   }
   sPaymenttermDescriptionX = {
      type: 'string',
      pattern: '/^.{1,40}$/',
      required: true
   }
   bPaymenttermIsactive = {
      type: 'boolean',
      required: true
   }
} 


