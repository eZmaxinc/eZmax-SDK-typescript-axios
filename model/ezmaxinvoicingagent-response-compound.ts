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
import { CustomContactNameResponse } from './custom-contact-name-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzmaxinvoicingagentResponse } from './ezmaxinvoicingagent-response';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzmaxinvoicingagentVariationezmax } from './field-eezmaxinvoicingagent-variationezmax';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzmaxinvoicingagentVariationezsign } from './field-eezmaxinvoicingagent-variationezsign';

/**
 * @type EzmaxinvoicingagentResponseCompound
 * A Ezmaxinvoicingagent Object
 * @export
 */
/** export type EzmaxinvoicingagentResponseCompound = EzmaxinvoicingagentResponse; */
export interface EzmaxinvoicingagentResponseCompound {
    /**
     * The unique ID of the Ezmaxinvoicingagent
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    pkiEzmaxinvoicingagentID?:number 
    /**
     * The unique ID of the Ezmaxinvoicing
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    fkiEzmaxinvoicingID?:number 
    /**
     * The unique ID of the Billingentityinternal.
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    fkiBillingentityinternalID:number 
    /**
     * The description of the Billingentityinternal in the language of the requester
     * @type {string}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    sBillingentityinternalDescriptionX:string 
    /**
     * The unique ID of the Agent.
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    fkiAgentID?:number 
    /**
     * The unique ID of the Broker.
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    fkiBrokerID?:number 
    /**
     * The number of sessions
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    iEzmaxinvoicingagentSession:number 
    /**
     * The number of times this user was cloned
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    iEzmaxinvoicingagentCloned:number 
    /**
     * The number of invoices
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    iEzmaxinvoicingagentInvoice:number 
    /**
     * The number of inscriptions
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    iEzmaxinvoicingagentInscription:number 
    /**
     * The number of active inscriptions
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    iEzmaxinvoicingagentInscriptionactive:number 
    /**
     * The number of sales
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    iEzmaxinvoicingagentSale:number 
    /**
     * The number of otherincomes
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    iEzmaxinvoicingagentOtherincome:number 
    /**
     * The number of commission calculations
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    iEzmaxinvoicingagentCommissioncalculation:number 
    /**
     * The number of ezsign documents
     * @type {number}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    iEzmaxinvoicingagentEzsigndocument:number 
    /**
     * Whether the agent has an eZsign account
     * @type {boolean}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    bEzmaxinvoicingagentEzsignaccount:boolean 
    /**
     * Whether it is billable for eZmax
     * @type {boolean}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    bEzmaxinvoicingagentBillableezmax:boolean 
    /**
     * 
     * @type {FieldEEzmaxinvoicingagentVariationezmax}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    eEzmaxinvoicingagentVariationezmax:FieldEEzmaxinvoicingagentVariationezmax 
    /**
     * Whether it is billable for eZsign
     * @type {boolean}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    bEzmaxinvoicingagentBillableezsign:boolean 
    /**
     * 
     * @type {FieldEEzmaxinvoicingagentVariationezsign}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    eEzmaxinvoicingagentVariationezsign:FieldEEzmaxinvoicingagentVariationezsign 
    /**
     * 
     * @type {CustomContactNameResponse}
     * @memberof EzmaxinvoicingagentResponseCompound
     */
    objContactName:CustomContactNameResponse 
}



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
 * A EzmaxinvoicingagentResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzmaxinvoicingagentResponseCompound
 */
export class DataObjectEzmaxinvoicingagentResponseCompound {
    pkiEzmaxinvoicingagentID?:number = undefined
    fkiEzmaxinvoicingID?:number = undefined
    fkiBillingentityinternalID:number = 0
    sBillingentityinternalDescriptionX:string = ''
    fkiAgentID?:number = undefined
    fkiBrokerID?:number = undefined
    iEzmaxinvoicingagentSession:number = 0
    iEzmaxinvoicingagentCloned:number = 0
    iEzmaxinvoicingagentInvoice:number = 0
    iEzmaxinvoicingagentInscription:number = 0
    iEzmaxinvoicingagentInscriptionactive:number = 0
    iEzmaxinvoicingagentSale:number = 0
    iEzmaxinvoicingagentOtherincome:number = 0
    iEzmaxinvoicingagentCommissioncalculation:number = 0
    iEzmaxinvoicingagentEzsigndocument:number = 0
    bEzmaxinvoicingagentEzsignaccount:boolean = false
    bEzmaxinvoicingagentBillableezmax:boolean = false
    eEzmaxinvoicingagentVariationezmax:FieldEEzmaxinvoicingagentVariationezmax = 'Charge'
    bEzmaxinvoicingagentBillableezsign:boolean = false
    eEzmaxinvoicingagentVariationezsign:FieldEEzmaxinvoicingagentVariationezsign = 'Charge'
    objContactName:CustomContactNameResponse = new DataObjectCustomContactNameResponse()
}

/**
 * @export 
 * A EzmaxinvoicingagentResponseCompound Validation Object
 * @class ValidationObjectEzmaxinvoicingagentResponseCompound
 */
export class ValidationObjectEzmaxinvoicingagentResponseCompound {
   pkiEzmaxinvoicingagentID = {
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
   fkiAgentID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiBrokerID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   iEzmaxinvoicingagentSession = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzmaxinvoicingagentCloned = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzmaxinvoicingagentInvoice = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzmaxinvoicingagentInscription = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzmaxinvoicingagentInscriptionactive = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzmaxinvoicingagentSale = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzmaxinvoicingagentOtherincome = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzmaxinvoicingagentCommissioncalculation = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   iEzmaxinvoicingagentEzsigndocument = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bEzmaxinvoicingagentEzsignaccount = {
      type: 'boolean',
      required: true
   }
   bEzmaxinvoicingagentBillableezmax = {
      type: 'boolean',
      required: true
   }
   eEzmaxinvoicingagentVariationezmax = {
      type: 'enum',
      allowableValues: ['Charge','Refund','Same'],
      required: true
   }
   bEzmaxinvoicingagentBillableezsign = {
      type: 'boolean',
      required: true
   }
   eEzmaxinvoicingagentVariationezsign = {
      type: 'enum',
      allowableValues: ['Charge','Refund','Same'],
      required: true
   }
   objContactName = new ValidationObjectCustomContactNameResponse()
} 


