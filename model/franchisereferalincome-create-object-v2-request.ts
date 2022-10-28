/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { FranchisereferalincomeRequestCompound } from './franchisereferalincome-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for POST /2/object/franchisereferalincome
 * @export
 * @interface FranchisereferalincomeCreateObjectV2Request
 */
export interface FranchisereferalincomeCreateObjectV2Request {
    /**
     * 
     * @type {Array<FranchisereferalincomeRequestCompound>}
     * @memberof FranchisereferalincomeCreateObjectV2Request
     */
    'a_objFranchisereferalincome': Array<FranchisereferalincomeRequestCompound>;
}
/**
 * A FranchisereferalincomeCreateObjectV2Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectFranchisereferalincomeCreateObjectV2Request
 */
export class DefaultObjectFranchisereferalincomeCreateObjectV2Request extends DefaultObject {
   a_objFranchisereferalincome:Array<FranchisereferalincomeRequestCompound> = []
}


