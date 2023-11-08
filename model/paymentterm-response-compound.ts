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
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEPaymenttermType } from './field-epaymentterm-type';
// May contain unused imports in some cases
// @ts-ignore
import { MultilingualPaymenttermDescription } from './multilingual-paymentterm-description';
// May contain unused imports in some cases
// @ts-ignore
import { PaymenttermResponse } from './paymentterm-response';

/**
 * @type PaymenttermResponseCompound
 * A Paymentterm Object
 * @export
 */
/** export type PaymenttermResponseCompound = PaymenttermResponse; */
export interface PaymenttermResponseCompound {
    /**
     * The unique ID of the Paymentterm
     * @type {number}
     * @memberof PaymenttermResponseCompound
     */
    pkiPaymenttermID:number 
    /**
     * The code of the Paymentterm
     * @type {string}
     * @memberof PaymenttermResponseCompound
     */
    sPaymenttermCode:string 
    /**
     * 
     * @type {FieldEPaymenttermType}
     * @memberof PaymenttermResponseCompound
     */
    ePaymenttermType:FieldEPaymenttermType 
    /**
     * The day of the Paymentterm
     * @type {number}
     * @memberof PaymenttermResponseCompound
     */
    iPaymenttermDay:number 
    /**
     * 
     * @type {MultilingualPaymenttermDescription}
     * @memberof PaymenttermResponseCompound
     */
    objPaymenttermDescription:MultilingualPaymenttermDescription 
    /**
     * Whether the Paymentterm is active or not
     * @type {boolean}
     * @memberof PaymenttermResponseCompound
     */
    bPaymenttermIsactive:boolean 
    /**
     * 
     * @type {CommonAudit}
     * @memberof PaymenttermResponseCompound
     */
    objAudit:CommonAudit 
}



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectMultilingualPaymenttermDescription } from './'
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectMultilingualPaymenttermDescription } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A PaymenttermResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPaymenttermResponseCompound
 */
export class DataObjectPaymenttermResponseCompound {
    pkiPaymenttermID:number = 0
    sPaymenttermCode:string = ''
    ePaymenttermType:FieldEPaymenttermType = 'Days'
    iPaymenttermDay:number = 0
    objPaymenttermDescription:MultilingualPaymenttermDescription = new DataObjectMultilingualPaymenttermDescription()
    bPaymenttermIsactive:boolean = false
    objAudit:CommonAudit = new DataObjectCommonAudit()
}

/**
 * @export 
 * A PaymenttermResponseCompound Validation Object
 * @class ValidationObjectPaymenttermResponseCompound
 */
export class ValidationObjectPaymenttermResponseCompound {
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
   objPaymenttermDescription = new ValidationObjectMultilingualPaymenttermDescription()
   bPaymenttermIsactive = {
      type: 'boolean',
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
} 

