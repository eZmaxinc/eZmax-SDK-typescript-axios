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
 * An Franchisereferalincome Object
 * @export
 * @interface FranchisereferalincomeRequest
 */
export interface FranchisereferalincomeRequest {
    /**
     * The unique ID of the Franchisereferalincome
     * @type {number}
     * @memberof FranchisereferalincomeRequest
     */
    /*'pkiFranchisereferalincomeID'?: number;*/
    'pkiFranchisereferalincomeID'?: number;
    /**
     * The unique ID of the Franchisebroker
     * @type {number}
     * @memberof FranchisereferalincomeRequest
     */
    /*'fkiFranchisebrokerID': number;*/
    'fkiFranchisebrokerID': number;
    /**
     * The unique ID of the Franchisereferalincomeprogram
     * @type {number}
     * @memberof FranchisereferalincomeRequest
     */
    /*'fkiFranchisereferalincomeprogramID': number;*/
    'fkiFranchisereferalincomeprogramID': number;
    /**
     * The unique ID of the Period
     * @type {number}
     * @memberof FranchisereferalincomeRequest
     */
    /*'fkiPeriodID': number;*/
    'fkiPeriodID': number;
    /**
     * The loan amount
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    /*'dFranchisereferalincomeLoan': string;*/
    'dFranchisereferalincomeLoan': string;
    /**
     * The amount that will be given to the franchise
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    /*'dFranchisereferalincomeFranchiseamount': string;*/
    'dFranchisereferalincomeFranchiseamount': string;
    /**
     * The amount that will be kept by the franchisor
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    /*'dFranchisereferalincomeFranchisoramount': string;*/
    'dFranchisereferalincomeFranchisoramount': string;
    /**
     * The amount that will be given to the agent
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    /*'dFranchisereferalincomeAgentamount': string;*/
    'dFranchisereferalincomeAgentamount': string;
    /**
     * The date the amounts were disbursed
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    /*'dtFranchisereferalincomeDisbursed': string;*/
    'dtFranchisereferalincomeDisbursed': string;
    /**
     * Comment about the transaction
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    /*'tFranchisereferalincomeComment': string;*/
    'tFranchisereferalincomeComment': string;
    /**
     * The unique ID of the Franchisereoffice
     * @type {number}
     * @memberof FranchisereferalincomeRequest
     */
    /*'fkiFranchiseofficeID': number;*/
    'fkiFranchiseofficeID': number;
    /**
     * 
     * @type {string}
     * @memberof FranchisereferalincomeRequest
     */
    /*'sFranchisereferalincomeRemoteid': string;*/
    'sFranchisereferalincomeRemoteid': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A FranchisereferalincomeRequest Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectFranchisereferalincomeRequest
 */
export class DataObjectFranchisereferalincomeRequest {
   pkiFranchisereferalincomeID?:number = undefined
   fkiFranchisebrokerID:number = 0
   fkiFranchisereferalincomeprogramID:number = 0
   fkiPeriodID:number = 0
   dFranchisereferalincomeLoan:string = ''
   dFranchisereferalincomeFranchiseamount:string = ''
   dFranchisereferalincomeFranchisoramount:string = ''
   dFranchisereferalincomeAgentamount:string = ''
   dtFranchisereferalincomeDisbursed:string = ''
   tFranchisereferalincomeComment:string = ''
   fkiFranchiseofficeID:number = 0
   sFranchisereferalincomeRemoteid:string = ''
}

/**
 * @export 
 * A FranchisereferalincomeRequest Validation Object
 * @class ValidationObjectFranchisereferalincomeRequest
 */
export class ValidationObjectFranchisereferalincomeRequest {
   pkiFranchisereferalincomeID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   fkiFranchisebrokerID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiFranchisereferalincomeprogramID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiPeriodID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   dFranchisereferalincomeLoan = {
      type: 'string',
      required: true
   }
   dFranchisereferalincomeFranchiseamount = {
      type: 'string',
      required: true
   }
   dFranchisereferalincomeFranchisoramount = {
      type: 'string',
      required: true
   }
   dFranchisereferalincomeAgentamount = {
      type: 'string',
      required: true
   }
   dtFranchisereferalincomeDisbursed = {
      type: 'string',
      required: true
   }
   tFranchisereferalincomeComment = {
      type: 'string',
      required: true
   }
   fkiFranchiseofficeID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sFranchisereferalincomeRemoteid = {
      type: 'string',
      required: true
   }
} 


