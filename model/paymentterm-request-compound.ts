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
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualPaymenttermDescription } from './multilingual-paymentterm-description';
// May contain unused imports in some cases
// @ts-ignore
import { PaymenttermRequest } from './paymentterm-request';

/**
 * @type PaymenttermRequestCompound
 * A Paymentterm Object and children
 * @export
 */
/** export type PaymenttermRequestCompound = PaymenttermRequest; */
export interface PaymenttermRequestCompound {
    /**
     * The unique ID of the Paymentterm
     * @type {number}
     * @memberof PaymenttermRequestCompound
     */
    pkiPaymenttermID?:number 
    /**
     * The code of the Paymentterm
     * @type {string}
     * @memberof PaymenttermRequestCompound
     */
    sPaymenttermCode:string 
    /**
     * 
     * @type {FieldEPaymenttermType}
     * @memberof PaymenttermRequestCompound
     */
    ePaymenttermType:FieldEPaymenttermType 
    /**
     * The day of the Paymentterm
     * @type {number}
     * @memberof PaymenttermRequestCompound
     */
    iPaymenttermDay:number 
    /**
     * 
     * @type {MultilingualPaymenttermDescription}
     * @memberof PaymenttermRequestCompound
     */
    objPaymenttermDescription:MultilingualPaymenttermDescription 
    /**
     * Whether the Paymentterm is active or not
     * @type {boolean}
     * @memberof PaymenttermRequestCompound
     */
    bPaymenttermIsactive:boolean 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualPaymenttermDescription } from './'
// @ts-ignore
import { ValidationObjectMultilingualPaymenttermDescription } from './'

/**
 * @export 
 * A PaymenttermRequestCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermRequestCompound
 */
export class DataObjectPaymenttermRequestCompound {
    pkiPaymenttermID?:number = undefined
    sPaymenttermCode:string = ''
    ePaymenttermType:FieldEPaymenttermType = 'Days'
    iPaymenttermDay:number = 0
    objPaymenttermDescription:MultilingualPaymenttermDescription = new DataObjectMultilingualPaymenttermDescription()
    bPaymenttermIsactive:boolean = false
}

/**
 * @export 
 * A PaymenttermRequestCompound Validation Object
 * @class ValidationObjectPaymenttermRequestCompound
 */
export class ValidationObjectPaymenttermRequestCompound {
   pkiPaymenttermID = {
      type: 'integer',
      required: false
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
   objPaymenttermDescription = new ValidationObjectMultilingualPaymenttermDescription()
   bPaymenttermIsactive = {
      type: 'boolean',
      required: true
   }
} 


