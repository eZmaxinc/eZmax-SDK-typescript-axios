/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { AddressRequest } from './address-request';
// May contain unused imports in some cases
// @ts-ignore
import { ContactRequestCompound } from './contact-request-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FranchisereferalincomeRequest } from './franchisereferalincome-request';
// May contain unused imports in some cases
// @ts-ignore
import { FranchisereferalincomeRequestCompoundAllOf } from './franchisereferalincome-request-compound-all-of';

import { DefaultObject } from '../base'

/**
 * @type FranchisereferalincomeRequestCompound
 * A Franchisereferalincome Object and children to create a complete structure
 * @export
 */
export type FranchisereferalincomeRequestCompound = FranchisereferalincomeRequest & FranchisereferalincomeRequestCompoundAllOf;


/**
 * @export 
 * A FranchisereferalincomeRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectFranchisereferalincomeRequestCompound
 */
export class DefaultObjectFranchisereferalincomeRequestCompound extends DefaultObject {
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
   objAddress:Partial<AddressRequest> = {}
   a_objContact:Array<ContactRequestCompound> = []
}


