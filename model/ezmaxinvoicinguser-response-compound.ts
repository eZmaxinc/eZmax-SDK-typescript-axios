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
import { CustomContactNameResponse } from './custom-contact-name-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingagentResponseCompoundAllOf } from './ezmaxinvoicingagent-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicinguserResponse } from './ezmaxinvoicinguser-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzmaxinvoicinguserVariationezsign } from './field-eezmaxinvoicinguser-variationezsign';

/**
 * @type EzmaxinvoicinguserResponseCompound
 * A Ezmaxinvoicinguser Object
 * @export
 */
export type EzmaxinvoicinguserResponseCompound = EzmaxinvoicingagentResponseCompoundAllOf & EzmaxinvoicinguserResponse;



/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomContactNameResponse } from './'
// @ts-ignore
import { ValidationObjectCustomContactNameResponse } from './'

/**
 * @export 
 * A EzmaxinvoicinguserResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicinguserResponseCompound
 */
export class DataObjectEzmaxinvoicinguserResponseCompound {
   pkiEzmaxinvoicinguserID?:number = undefined
   fkiEzmaxinvoicingID?:number = undefined
   fkiBillingentityinternalID:number = 0
   sBillingentityinternalDescriptionX:string = ''
   fkiUserID:number = 0
   iEzmaxinvoicinguserEzsigndocument:number = 0
   bEzmaxinvoicinguserEzsignaccount:boolean = false
   bEzmaxinvoicinguserBillableezsign:boolean = false
   eEzmaxinvoicinguserVariationezsign:FieldEEzmaxinvoicinguserVariationezsign = 'Charge'
   objContactName:CustomContactNameResponse = new DataObjectCustomContactNameResponse()
}

/**
 * @export 
 * A EzmaxinvoicinguserResponseCompound Validation Object
 * @class ValidationObjectEzmaxinvoicinguserResponseCompound
 */
export class ValidationObjectEzmaxinvoicinguserResponseCompound {
   pkiEzmaxinvoicinguserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiEzmaxinvoicingID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiBillingentityinternalID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sBillingentityinternalDescriptionX = {
      type: 'string',
      required: true
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzmaxinvoicinguserEzsigndocument = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzmaxinvoicinguserEzsignaccount = {
      type: 'boolean',
      required: true
   }
   bEzmaxinvoicinguserBillableezsign = {
      type: 'boolean',
      required: true
   }
   eEzmaxinvoicinguserVariationezsign = {
      type: 'enum',
      allowableValues: ['Charge','Refund','Same'],
      required: true
   }
   objContactName = new ValidationObjectCustomContactNameResponse()
} 


