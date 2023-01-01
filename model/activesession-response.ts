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
import { FieldEActivesessionUsertype } from './field-eactivesession-usertype';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEActivesessionWeekdaystart } from './field-eactivesession-weekdaystart';

import { DefaultObject } from '../base'

/**
 * An Activesession Object
 * @export
 * @interface ActivesessionResponse
 */
export interface ActivesessionResponse {
    /**
     * 
     * @type {FieldEActivesessionUsertype}
     * @memberof ActivesessionResponse
     */
    'eActivesessionUsertype': FieldEActivesessionUsertype;
    /**
     * 
     * @type {FieldEActivesessionWeekdaystart}
     * @memberof ActivesessionResponse
     */
    'eActivesessionWeekdaystart': FieldEActivesessionWeekdaystart;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof ActivesessionResponse
     */
    'fkiLanguageID': number;
    /**
     * The Name of the Company in the language of the requester
     * @type {string}
     * @memberof ActivesessionResponse
     */
    'sCompanyNameX': string;
    /**
     * The Name of the Department in the language of the requester
     * @type {string}
     * @memberof ActivesessionResponse
     */
    'sDepartmentNameX': string;
    /**
     * Whether the active session is in debug or not
     * @type {boolean}
     * @memberof ActivesessionResponse
     */
    'bActivesessionDebug': boolean;
    /**
     * Whether the active session is superadmin or not
     * @type {boolean}
     * @memberof ActivesessionResponse
     */
    'bActivesessionIssuperadmin': boolean;
    /**
     * The customer code assigned to your account
     * @type {string}
     * @memberof ActivesessionResponse
     */
    'pksCustomerCode': string;
    /**
     * The unique ID of the Systemconfigurationtype
     * @type {number}
     * @memberof ActivesessionResponse
     */
    'fkiSystemconfigurationtypeID'?: number;
}
/**
 * A ActivesessionResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectActivesessionResponse
 */
export class DefaultObjectActivesessionResponse extends DefaultObject {
   eActivesessionUsertype:FieldEActivesessionUsertype = 'AgentBroker'
   eActivesessionWeekdaystart:FieldEActivesessionWeekdaystart = 'Sunday'
   fkiLanguageID:number = 0
   sCompanyNameX:string = ''
   sDepartmentNameX:string = ''
   bActivesessionDebug:boolean = false
   bActivesessionIssuperadmin:boolean = false
   pksCustomerCode:string = ''
   fkiSystemconfigurationtypeID?:number = undefined
}


