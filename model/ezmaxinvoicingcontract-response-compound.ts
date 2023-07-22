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
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingcontractResponse } from './ezmaxinvoicingcontract-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzmaxinvoicingcontractPaymenttype } from './field-eezmaxinvoicingcontract-paymenttype';

/**
 * @type EzmaxinvoicingcontractResponseCompound
 * A Ezmaxinvoicingcontract Object
 * @export
 */
export type EzmaxinvoicingcontractResponseCompound = EzmaxinvoicingcontractResponse;



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A EzmaxinvoicingcontractResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingcontractResponseCompound
 */
export class DataObjectEzmaxinvoicingcontractResponseCompound {
    pkiEzmaxinvoicingcontractID:number = 0
    eEzmaxinvoicingcontractPaymenttype:FieldEEzmaxinvoicingcontractPaymenttype = 'Cheque'
    iEzmaxinvoicingcontractLength:number = 0
    dtEzmaxinvoicingcontractStart:string = ''
    dtEzmaxinvoicingcontractEnd:string = ''
    dEzmaxinvoicingcontractLicense:string = ''
    dEzmaxinvoicingcontract121qa:string = ''
    bEzmaxinvoicingcontractEzsignallagents:boolean = false
    objAudit:CommonAudit = new DataObjectCommonAudit()
}

/**
 * @export 
 * A EzmaxinvoicingcontractResponseCompound Validation Object
 * @class ValidationObjectEzmaxinvoicingcontractResponseCompound
 */
export class ValidationObjectEzmaxinvoicingcontractResponseCompound {
   pkiEzmaxinvoicingcontractID = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   eEzmaxinvoicingcontractPaymenttype = {
      type: 'enum',
      allowableValues: ['Cheque','CreditCard','DirectDebit'],
      required: true
   }
   iEzmaxinvoicingcontractLength = {
      type: 'integer',
      minimum: 1,
      required: true
   }
   dtEzmaxinvoicingcontractStart = {
      type: 'string',
      required: true
   }
   dtEzmaxinvoicingcontractEnd = {
      type: 'string',
      required: true
   }
   dEzmaxinvoicingcontractLicense = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   dEzmaxinvoicingcontract121qa = {
      type: 'string',
      pattern: '/^-{0,1}[\d]{1,9}?\.[\d]{2}$/',
      required: true
   }
   bEzmaxinvoicingcontractEzsignallagents = {
      type: 'boolean',
      required: true
   }
   objAudit = new ValidationObjectCommonAudit()
} 


